# 本地信封加密与密钥管理（Envelope Key Management, EKM）

一个完全本地运行、不依赖任何外部服务和真实凭据的信封加密（Envelope Encryption）与密钥管理示例服务。
使用本地文件模拟主密钥（KEK）持久化与审计日志，覆盖：请求负载加解密、主密钥轮换、调用方权限控制、
可区分的错误分类和完整审计留痕。

- Java 21+ / Spring Boot 3.4 / 仅 JDK 内置 JCE（AES-256-GCM），无外部 KMS/HSM/数据库
- 本地存储目录 `./local-data/`（可用 `ekm.local.dir` 覆盖）：
  - `keys.properties`：全部历史主密钥（Base64），原子写
  - `audit.log`：TSV 审计日志，按行追加

---

## 1. 密钥层级与版本含义

```
主密钥 KEK（AES-256，版本 1、2、3…，长期保存在 keys.properties）
   └── 包装/解包（AES-GCM，每次随机 IV，带 128 位认证标签）
          数据密钥 DEK（AES-256，每次加密请求新生成一把）
             └── 加解密请求负载（AES-256-GCM，每次随机 IV）
```

- **主密钥（KEK）**：只用于加解密 DEK，从不直接接触业务明文。版本号从 `1` 开始，单调递增。
  所有历史版本永久保留在本地文件中，供旧密文解密使用。
- **数据密钥（DEK）**：每次 `encrypt` 都新生成一把随机 DEK 与随机 IV，因此**同一明文每次密文都不同**；
  明文 DEK 只在单次请求内存在于内存，用后清零；随密文持久化的只有“被 KEK 包装的 DEK”。
- **信封密文格式**（二进制后做标准 Base64）：

  ```
  "EKM1" | 结构版本(1B) | KEK版本(int32)
        | DEK_ID长度(2B) | DEK_ID
        | 包装DEK长度(2B) | 包装DEK = IV(12B) + AES-GCM(DEK)(含16B标签)
        | 负载IV长度(2B)  | 负载IV(12B)
        | 负载密文长度(4B) | AES-GCM(明文)(含16B标签)
  ```
  长度字段均为大端序。密文自描述其 KEK 版本，服务端据此选择对应历史主密钥解包。

## 2. 轮换规则

- 轮换（`POST /api/v1/keys/rotate`，需 `ROTATE` 权限）在存储层用同一把锁串行化：
  - 新版本号 = 当前最大版本 + 1，**并发/重复轮换绝不会产生重复版本，也不会互相打断**；
  - 新版本先写 `keys.properties.tmp` 再原子替换，任何读操作都不会读到写一半的中间状态；
  - 写盘失败会回滚内存状态，保持内存与文件一致。
- 轮换后：
  - **新加密**自动使用当前（最新版本）KEK 生成 DEK；
  - **历史密文**仍用密文头中记录的旧版本 KEK 解包，可正确解密（多轮轮换同样适用）；
  - 轮换进行中的并发加密/解密不会失败：解包按密文自带版本取 KEK，与轮换互不影响。

## 3. 调用方与权限

身份通过请求体 `callerId` 传递（本地模拟，无真实凭据）。内置调用方：

| callerId          | 权限                       | 典型操作           |
|-------------------|----------------------------|--------------------|
| `app-crypto`      | ENCRYPT, DECRYPT           | 业务加解密         |
| `app-encrypt-only`| ENCRYPT                    | 只采集加密、不能解 |
| `key-admin`       | ROTATE, AUDIT_READ         | 轮换、查审计/版本  |
| `auditor`         | AUDIT_READ                 | 只读审计           |
| 其他/缺失         | 无                         | 一律 ACCESS_DENIED |

## 4. 错误分类（可区分、可复现）

所有错误返回统一 JSON：`{code, category, message, detail}`，并映射到不同 HTTP 状态：

| code                   | category   | HTTP | 触发情形                                               |
|------------------------|------------|------|--------------------------------------------------------|
| `INVALID_PARAMETER`    | PARAM      | 400  | plaintext/ciphertext 空、请求体不是 JSON 等            |
| `MALFORMED_CIPHERTEXT` | CIPHERTEXT | 400  | Base64 非法、魔数不是 EKM1、结构版本不支持             |
| `CIPHERTEXT_TRUNCATED` | CIPHERTEXT | 400  | 头部有效但声明长度与实际字节不符（被截断）             |
| `CIPHERTEXT_TAMPERED`  | INTEGRITY  | 400  | 结构完整但 AES-GCM 认证失败（负载/包装层任一字节被改） |
| `KEY_VERSION_NOT_FOUND`| KEY        | 404  | 密文引用的 KEK 版本不存在                              |
| `ACCESS_DENIED`        | AUTHZ      | 403  | 调用方未知、缺失身份或没有所需权限                     |
| `INTERNAL_ERROR`       | INTERNAL   | 500  | 未预期服务端错误                                       |

关键性质：格式校验先于任何密码学操作，篡改由 AEAD 标签在解密阶段拦截，
**任何异常输入下都不会返回错误的明文**。

## 5. 审计

- 每次 `ENCRYPT` / `DECRYPT` / `ROTATE` 成功写 `SUCCESS`；业务失败写 `REQUEST_REJECTED/FAILURE`
  （含错误码与判定依据）；越权写 `ACCESS_DENIED/DENIED`。
- 记录字段：单调递增 `id`、UTC `timestamp`、`callerId`、`action`、`result`、`detail`
  （含 KEK 版本、DEK ID、错误码等判定依据）。
- 写入串行化 + 单行原子追加，并发写入不丢记录、不交错；可通过
  `GET /api/v1/audit?callerId=...&action=...` 查询（需 AUDIT_READ），文件在 `local-data/audit.log`。

## 6. HTTP 接口

| 方法 | 路径                          | 权限       | 说明                 |
|------|-------------------------------|------------|----------------------|
| POST | `/api/v1/encrypt`             | ENCRYPT    | 入参 `{callerId, plaintext}`，返回 `{ciphertext, masterKeyVersion, dataKeyId}` |
| POST | `/api/v1/decrypt`             | DECRYPT    | 入参 `{callerId, ciphertext}`，返回 `{plaintext}` |
| POST | `/api/v1/keys/rotate`         | ROTATE     | 返回 `{newVersion, createdAt}` |
| GET  | `/api/v1/keys/current?callerId=` | AUDIT_READ | 查询当前 KEK 版本 |
| GET  | `/api/v1/audit?callerId=&action=` | AUDIT_READ | 查询审计记录 |

## 7. 本地验证方式

前置：JDK 21+、Maven 3.9+（无需任何外部服务）。

```bash
# 1) 全量测试（30 个用例：篡改/截断、旧版本解密、轮换并发、越权、审计不丢记录）
mvn test

# 2) 启动服务（随机端口，启动日志可见端口；也可在 application.properties 固定 server.port）
mvn spring-boot:run

# 3) 手工验证（另开终端；若固定了端口把 0 换成实际端口）
./scripts/local-smoke.sh   # 脚本内用固定 8080 端口启动并完成加解密/篡改/轮换/越权/审计全流程
```

### curl 快速示例

```bash
curl -s -X POST localhost:8080/api/v1/encrypt -H 'Content-Type: application/json' \
  -d '{"callerId":"app-crypto","plaintext":"hello"}'
# 用返回的 ciphertext 解密
curl -s -X POST localhost:8080/api/v1/decrypt -H 'Content-Type: application/json' \
  -d '{"callerId":"app-crypto","ciphertext":"<上一步 ciphertext>"}'
# 轮换
curl -s -X POST localhost:8080/api/v1/keys/rotate -H 'Content-Type: application/json' \
  -d '{"callerId":"key-admin"}'
# 越权（app-crypto 尝试轮换 -> 403 ACCESS_DENIED）
curl -i -s -X POST localhost:8080/api/v1/keys/rotate -H 'Content-Type: application/json' \
  -d '{"callerId":"app-crypto"}'
# 查审计
curl -s 'localhost:8080/api/v1/audit?callerId=key-admin'
```

## 8. 测试覆盖一览

| 测试类                    | 覆盖内容                                                                 |
|---------------------------|--------------------------------------------------------------------------|
| `EnvelopeCiphertextParseTest` | Base64 非法 / 魔数错 / 截断 / 空值的错误分类与可区分性                |
| `CoreEnvelopeServiceTest` | 同明文密文不同且往返；负载与包装层篡改；截断；非法格式；版本不存在；轮换前后与多轮换历史密文可解 |
| `ConcurrencyTest`         | 20 路并发轮换版本唯一递增；轮换期间 8 路加密+4 路轮换全部成功；500 条并发审计无丢失 |
| `AccessControlTest`       | 缺权限/未知调用方拒绝；AUTHZ(403) 与 PARAM(400)/KEY(404) 可区分；拒绝留痕 |
| `WebIntegrationTest`      | 端到端 HTTP：往返、轮换后旧密文可解、篡改/截断/缺版本/越权的状态码与错误体、审计查询 |
| `ApplicationTests`        | Spring 上下文装配与首个主密钥自动初始化                                  |

测试日志通过 SLF4J 打印关键输入（密文长度、篡改字节位置、伪造版本号、调用方）与判定依据（错误码、category、KEK/DEK 标识、审计序号），可用 `mvn test` 直接观察。
