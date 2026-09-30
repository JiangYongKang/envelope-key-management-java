#!/usr/bin/env bash
# 本地端到端冒烟：启动服务 -> 加解密 -> 篡改/截断 -> 轮换 -> 旧密文可解 -> 越权 -> 审计，最后关闭服务。
# 仅依赖 JDK/Maven 与 python3（标准库），无外部服务。
set -u
PORT="${1:-8080}"
BASE="http://127.0.0.1:${PORT}/api/v1"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR/.."
rm -rf local-data

echo ">> 启动服务（端口 ${PORT}）..."
mvn -q spring-boot:run -Dspring-boot.run.arguments="--server.port=${PORT}" >/tmp/ekm-smoke.log 2>&1 &
MVN_PID=$!
cleanup() {
  kill "$MVN_PID" 2>/dev/null
  pkill -P "$MVN_PID" 2>/dev/null
  wait "$MVN_PID" 2>/dev/null
}
trap cleanup EXIT

echo ">> 等待服务就绪..."
for i in $(seq 1 90); do
  curl -s --noproxy "*" "${BASE}/keys/current?callerId=key-admin" 2>/dev/null | grep -q newVersion && break
  sleep 1
done
curl -s --noproxy "*" "${BASE}/keys/current?callerId=key-admin" 2>/dev/null | grep -q newVersion \
  || { echo "服务未启动，见 /tmp/ekm-smoke.log"; exit 1; }

export BASE
python3 - <<'PY'
import base64
import json
import os
import sys
import urllib.request

# 绕过环境中的 HTTP 代理，直连本地服务
_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
urllib.request.install_opener(_direct)
import urllib.error

BASE = os.environ["BASE"]

def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def check(name, cond, detail=""):
    print(f"   [{'PASS' if cond else 'FAIL'}] {name} {detail}")
    if not cond:
        sys.exit(1)

st, c1 = call("POST", "/encrypt", {"callerId": "app-crypto", "plaintext": "smoke-秘密"})
st2, c2 = call("POST", "/encrypt", {"callerId": "app-crypto", "plaintext": "smoke-秘密"})
check("同一明文两次密文不同", c1["ciphertext"] != c2["ciphertext"])
check("新密文落在 v1", c1["masterKeyVersion"] == 1, f"version={c1['masterKeyVersion']}")

st, d1 = call("POST", "/decrypt", {"callerId": "app-crypto", "ciphertext": c1["ciphertext"]})
check("正常解密还原", st == 200 and d1["plaintext"] == "smoke-秘密")

raw = bytearray(base64.b64decode(c1["ciphertext"]))
short = base64.b64encode(bytes(raw[:-16])).decode()
st, body = call("POST", "/decrypt", {"callerId": "app-crypto", "ciphertext": short})
check("截断 -> CIPHERTEXT_TRUNCATED/400",
      st == 400 and body["code"] == "CIPHERTEXT_TRUNCATED", body.get("category"))

tamp = bytearray(raw)
tamp[-2] ^= 0x01
st, body = call("POST", "/decrypt",
                {"callerId": "app-crypto", "ciphertext": base64.b64encode(bytes(tamp)).decode()})
check("篡改 -> CIPHERTEXT_TAMPERED/400",
      st == 400 and body["code"] == "CIPHERTEXT_TAMPERED", body.get("category"))

bad_ver = bytearray(raw)
bad_ver[5:9] = (999).to_bytes(4, "big")
st, body = call("POST", "/decrypt",
                {"callerId": "app-crypto", "ciphertext": base64.b64encode(bytes(bad_ver)).decode()})
check("版本不存在 -> KEY_VERSION_NOT_FOUND/404",
      st == 404 and body["code"] == "KEY_VERSION_NOT_FOUND", body.get("category"))

st, rot = call("POST", "/keys/rotate", {"callerId": "key-admin"})
check("轮换成功到 v2", st == 200 and rot["newVersion"] == 2)

st, d_old = call("POST", "/decrypt", {"callerId": "app-crypto", "ciphertext": c1["ciphertext"]})
check("轮换后旧密文仍可解", st == 200 and d_old["plaintext"] == "smoke-秘密")

st, c3 = call("POST", "/encrypt", {"callerId": "app-crypto", "plaintext": "new-era"})
check("新密文使用 v2", c3["masterKeyVersion"] == 2)

st, body = call("POST", "/keys/rotate", {"callerId": "app-crypto"})
check("越权轮换 -> ACCESS_DENIED/403",
      st == 403 and body["code"] == "ACCESS_DENIED", body.get("category"))

st, events = call("GET", "/audit?callerId=key-admin", None)
actions = [e["action"] for e in events]
check("审计可查且含 ROTATE/ACCESS_DENIED",
      st == 200 and "ROTATE" in actions and "ACCESS_DENIED" in actions,
      f"events={len(events)}")
print(">> 全部冒烟断言通过")
PY

echo ">> 冒烟完成，关闭服务"
