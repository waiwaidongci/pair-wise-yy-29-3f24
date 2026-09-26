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
- `POST /api/batches`：批量签发台，`template_id` + `rows_text`，每行 `持有人 ⇥ 声明字段… ⇥ 业务编号`（支持从表格粘贴的 Tab 分隔，也兼容逗号；首行可以是表头）。每行判为 `issued`（签出）、`replayed`（沿用原单）或 `rejected`（被某个条件挡住，带 `condition` 与原因）。同一批重复业务编号沿用首次结果；有效行照常签发，错误行不落凭证记录。
- `GET /api/batches`、`GET /api/batches/{id}`：查看本人的批次总数与逐行结果。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

首页（`/`）是批量签发台：选择模板后粘贴名单，提交即可看到逐行结果、总数统计和历史批次。批量功能按职责分三层：`batch.py` 只做批次判定（解析、查重、复用单张签发规则），`Store` 负责批次与逐行记录落库（`issuance_batches`、`issuance_batch_rows`），`static/index.html` 负责页面交互。原有的单张签发、出示和验证接口保持不变。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。
