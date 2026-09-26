# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `POST /api/batches`：批量签发。请求体 `{template_id, roster}`，`roster` 为按模板粘贴的文本：首行表头必须含 `业务编号`、`持有人` 两列，其余列对应模板声明字段，支持制表符或英文逗号分隔。逐行返回 `issued`（新签出）、`reused`（沿用本批首次结果或历史原单，业务编号即幂等键）或 `blocked`（附挡住原因）；错误行不产生凭证，但逐行结果与计数都会落库。空名单、缺少必填列表头等结构性问题整批 400 拒绝，不落批次。
- `GET /api/batches`：本签发方的批次列表（含每批签出/沿用/挡住计数）。
- `GET /api/batches/{id}`：某批次的逐行结果。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

首页（`GET /`）提供「批量签发台」和「批次记录」两个页面。职责按层分开：`parse_roster_text` 只解析文本，`BatchService` 只做逐行判定并复用 `CredentialService.issue` 完成单张签发，`Store.save_batch` 只负责批次与逐行结果落库；原单张签发、出示、验证接口不受影响。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
