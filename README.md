# 本地信封加密与密钥管理（Envelope Key Management）

一个**完全本地、无外部服务、无真实凭据**的信封加密（Envelope Encryption）与
密钥生命周期管理示例，基于 Spring Boot 3 / Java 21。主密钥、数据密钥与审计记录
都用工作目录下的 JSON 文件模拟，开箱即可运行和复现。

## 1. 密钥层级与版本含义

采用两层密钥模型（信封加密）：

```
主密钥 MK（Master Key，按“版本”保存，明文不出本进程，用 SecureRandom 本地生成）
   └── 包裹（AES-256-GCM 加密 + 认证）数据密钥 DEK
            └── DEK 直接加密业务请求负载（AES-256-GCM）
```

- **主密钥 MK**：顶层密钥，32 字节，按版本号 `v1, v2, ...` 保存于
  `data/master-keys.json`。轮换**只新增版本、永不删除历史版本**，因此旧密文
  永远能用对应旧版本解开。首次启动若文件不存在会自动引导生成 `v1`。
- **数据密钥 DEK**：每次加密请求都新建一把 32 字节 DEK（因此同一明文每次密文不同）。
  DEK 由“当时的最新主密钥版本”包裹后存于 `data/data-keys.json`；
  **明文 DEK 只在单次请求内存中短暂出现，绝不落盘**。
- **密文信封格式**（文本，便于演示与篡改测试）：

  ```
  EKM1:<主密钥版本号>.<b64url keyId>.<b64url wrappingIv>.<b64url wrappedDek>.<b64url payloadIv>.<b64url payloadCiphertext>
  ```

  版本号是对主密钥的**显式引用**（明文数字，供路由查版本）；同时版本号与 keyId
  被写入包裹层和负载层 GCM 的 AAD，任何改动都会让认证标签失效。

## 2. 轮换规则

- `POST /api/keys/rotate`（需要 `ROTATE` 权限）生成一把全新主密钥并追加为下一版本，
  版本号严格单调、绝不复用。
- **轮换后新产生的数据一律使用新版本**；历史密文头部仍引用旧版本，用旧版本解开。
- **并发/重复轮换“窗口合批”**：在领头条目真正写入新版本的窗口内到达的其它轮换请求
  会等待并复用同一个新版本，因此：
  - 不会产生重复版本，也不会跳过版本；
  - 不会打断正在进行的轮换；
  - 窗口结束后的后续请求会正常开启下一轮、再产生新版本。
- 写新版本发生在轮换锁之外，加解密路径不抢该锁；主密钥存储读取与“临时文件 +
  原子 move”落盘保证轮换任意瞬间读到的版本都完整一致，故**轮换期间并发的加密/解密
  不会因中间状态失败**（见并发测试，480 次加解密零失败）。

## 3. 调用方权限与审计

身份通过请求头 `X-Caller-Id` 传入（本地目录模拟，无真实凭据）：

| 调用方 | 权限 |
| --- | --- |
| `svc-enc` | ENCRYPT |
| `svc-dec` | ENCRYPT, DECRYPT |
| `key-admin` | ENCRYPT, DECRYPT, ROTATE |
| `auditor` | AUDIT_READ |
| `svc-limited` | 无权限（用于演示拒绝） |

- 越权统一返回 `ACCESS_DENIED`，但消息可区分：**身份未知/未提供头** vs
  **身份已知但缺少某项权限**。
- 密钥使用（ENCRYPT/DECRYPT/GENERATE_DATA_KEY）、ROTATE、AUDIT_QUERY 以及每次
  **被拒绝**的请求（ACCESS_DENIED）都写入 `data/audit-log.json`，记录包含
  事件 ID、时间戳、调用方、操作类型、成功与否、目标与详情。
- 审计追加在同一把监视器锁内“入内存 + 全量序列化 + 原子落盘”一次完成，
  **并发写入不丢记录**（测试覆盖 20 线程 × 100 条）。

## 4. 错误分类（彼此可区分）

| errorCode | HTTP | 触发场景 |
| --- | --- | --- |
| `INVALID_PARAMETER` | 400 | 明文为空、请求体缺失/非法 JSON、action 参数非法等 |
| `CIPHERTEXT_MALFORMED` | 400 | 前缀错误、段数不对（截断）、版本号非数字、Base64 非法、IV/密文长度非法 |
| `CIPHERTEXT_TAMPERED` | 422 | 结构合法但 GCM 认证标签不匹配：负载/包裹密文被改、版本被改成**另一个存在的版本**、keyId 与版本对不上 |
| `KEY_VERSION_NOT_FOUND` | 404 | 密文引用的主密钥版本不存在或已停用（例如改成 v9999） |
| `DATA_KEY_NOT_FOUND` | 404 | 密文引用的 keyId 在数据密钥库中不存在 |
| `ACCESS_DENIED` | 403 | 未提供/未知调用方，或调用方缺少所需权限 |

判定顺序保证结论唯一：**先查密文结构 → 再查 DEK 是否存在 → 再查引用的主版本是否存在
→ 再比对版本与 DEK 记录一致性 → 再验包裹层标签 → 最后验负载标签**。
任何一步失败都只抛错，**任何情况下都不会返回错误明文**。

## 5. HTTP 接口

| 方法与路径 | 权限 | 说明 |
| --- | --- | --- |
| `POST /api/keys/encrypt` | ENCRYPT | body `{"plaintext":"..."}` → `{"ciphertext":"EKM1:..."}` |
| `POST /api/keys/decrypt` | DECRYPT | body `{"ciphertext":"..."}` → `{"plaintext":"..."}` |
| `POST /api/keys/rotate` | ROTATE | 追加一个主密钥新版本 |
| `GET  /api/keys/status` | 任意已知身份 | 返回当前版本与全部历史版本号 |
| `GET  /api/keys/audit?caller=&action=` | AUDIT_READ | 查询审计记录（可按调用方/操作类型过滤） |

## 6. 本地验证

需要 JDK 21+（在 JDK 25 上同样可构建）与 Maven。

```bash
# 运行全部单元/集成测试（含篡改、截断、旧版本解密、轮换并发、越权、审计并发）
mvn test

# 启动服务（随机端口），本地文件落在 ./data
mvn spring-boot:run
# 可用 -Dekm.data-dir=/path/to/dir 改变本地存储目录
```

curl 手动验证：

```bash
# 加密
curl -s -X POST localhost:8080/api/keys/encrypt \
  -H 'X-Caller-Id: svc-dec' -H 'Content-Type: application/json' \
  -d '{"plaintext":"hello-机密"}'

# 解密（把上一步 ciphertext 填入）
curl -s -X POST localhost:8080/api/keys/decrypt \
  -H 'X-Caller-Id: svc-dec' -H 'Content-Type: application/json' \
  -d '{"ciphertext":"EKM1:1...."}'

# 轮换主密钥（仅 key-admin）
curl -s -X POST localhost:8080/api/keys/rotate -H 'X-Caller-Id: key-admin'

# 越权示例（svc-dec 无 ROTATE）→ 403 ACCESS_DENIED
curl -i -s -X POST localhost:8080/api/keys/rotate -H 'X-Caller-Id: svc-dec'

# 查询审计（仅 auditor）
curl -s localhost:8080/api/keys/audit -H 'X-Caller-Id: auditor'
```

## 7. 测试覆盖与可观测性

- `EnvelopeCodecTest`：格式非法 / 截断 / 版本号非法归类。
- `EnvelopeEncryptionServiceTest`：同明文不同密文且都解回、空参数、截断、
  负载/包裹层篡改、引用不存在版本、改成存在版本、keyId 不存在、多类异常输入绝不返回明文。
- `KeyRotationTest`：轮换后新数据用新版本、旧密文仍可解、版本严格单调、轮换有审计。
- `KeyRotationConcurrencyTest`：16 并发轮换合批为单一新版本；12 线程 × 40 次
  加解密在轮换窗口内零失败、结果一致。
- `AuthorizationAuditTest`：越权原因区分、拒绝留痕、密钥使用/轮换留痕、20×100
  并发审计写入内存与磁盘零丢失。
- `WebApiIntegrationTest`：真实 MVC 下 200/400/403/404/422 与 errorCode 的一一对应。

测试日志会打印**关键输入**（明文、密文片段、被改字段、并发规模）与**判定依据**
（实际 errorCode、HTTP 状态、错误消息），便于复现和核对分类。

## 8. 本地存储文件

- `data/master-keys.json`：主密钥各版本（含 Base64 密钥材料）。
- `data/data-keys.json`：数据密钥的包裹形态、wrappingIv、所属主版本。
- `data/audit-log.json`：审计事件数组。

> 这些文件仅为本机演示用，目录已加入 `.gitignore`；删除后重启会重新引导 v1。
> 请勿把本示例的明文主密钥文件方案用于生产。
