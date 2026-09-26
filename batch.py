#!/usr/bin/env python3
"""批量签发的批次判定层。

职责边界：本模块只把粘贴文本逐行判成 ``issued`` / ``replayed`` / ``rejected``；
记录落库走 :class:`app.Store`，交互界面走 ``static/index.html``。
单张签发仍走 :meth:`app.CredentialService.issue`，本层只做编排，不另写签发规则。
"""
from __future__ import annotations

import json
import uuid

from app import ApiError, iso

# 允许老师连表头一起粘贴：首格/末格命中这些词时按表头跳过。
HEADER_FIRST = {"持有人", "holder", "holder_id"}
HEADER_LAST = {"业务编号", "业务号", "业务键", "idempotency_key", "business_key"}


def parse_batch_text(text: str) -> list[tuple[int, list[str]]]:
    """把粘贴内容拆成 ``(原始行号, 单元格列表)``，跳过空行和表头行。"""
    parsed: list[tuple[int, list[str]]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        # 不能先对整行 strip：行首/行尾分隔符代表“持有人为空”等空单元格。
        separator = "\t" if "\t" in raw else ","
        parsed.append((line_no, [cell.strip() for cell in raw.split(separator)]))
    if (
        parsed
        and len(parsed[0][1]) >= 2
        and parsed[0][1][0] in HEADER_FIRST
        and parsed[0][1][-1] in HEADER_LAST
    ):
        parsed = parsed[1:]
    return parsed


class BatchService:
    """批量签发判定：每行签出、沿用原单或被某个条件挡住。"""

    def __init__(self, service):
        self.service = service
        self.store = service.store
        self.conn = service.conn

    @staticmethod
    def _condition(exc: ApiError) -> str:
        if "已有有效的同模板凭证" in exc.message:
            return "active_credential_exists"
        return {400: "invalid_row", 403: "forbidden", 409: "conflict"}.get(exc.status, "rejected")

    def submit(self, actor: str | None, role: str | None, template_id: object, rows_text: object) -> dict:
        actor = self.service._required_actor(actor, role, "issuer")
        try:
            template_id = int(template_id)
        except (TypeError, ValueError) as exc:
            raise ApiError(400, "模板编号无效") from exc
        # 整批前置条件不满足时直接拒绝，不产生批次记录。
        template = self.service._row("templates", template_id)
        if template["issuer"] != actor:
            raise ApiError(403, "不能使用其他签发方的模板")
        if template["status"] != "active":
            raise ApiError(409, "模板已停用")
        self.service._active_key(actor)
        if not isinstance(rows_text, str) or not rows_text.strip():
            raise ApiError(400, "请粘贴至少一行签发记录")

        fields = json.loads(template["fields_json"])
        expected_columns = len(fields) + 2  # 持有人 + 各声明字段 + 业务编号
        parsed = parse_batch_text(rows_text)
        if not parsed:
            raise ApiError(400, "没有可签发的记录行")

        seen: dict[str, dict] = {}  # 本批业务编号 -> 首次结果
        rows: list[dict] = []
        counts = {"issued": 0, "replayed": 0, "rejected": 0}

        def add_row(row: dict, register_key: bool = True) -> None:
            rows.append(row)
            counts[row["status"]] += 1
            if register_key and row["business_key"]:
                seen.setdefault(row["business_key"], row)

        for line_no, cells in parsed:
            row = {
                "line_no": line_no,
                "holder_id": "",
                "business_key": "",
                "claims": None,
                "status": "rejected",
                "condition": None,
                "reason": None,
                "credential_id": None,
                "duplicate_of_line": None,
            }
            if len(cells) != expected_columns:
                row["condition"] = "bad_columns"
                row["reason"] = (
                    f"列数不符：应为 {expected_columns} 列"
                    f"（持有人 / {len(fields)} 个声明字段 / 业务编号），实际 {len(cells)} 列"
                )
                add_row(row)
                continue

            holder, key = cells[0], cells[-1]
            row["holder_id"], row["business_key"] = holder, key
            claims = {
                field["name"]: value
                for field, value in zip(fields, cells[1:-1])
                if value
            }
            row["claims"] = claims

            if not holder:
                row["condition"], row["reason"] = "missing_holder", "持有人为空"
                add_row(row)
                continue
            if not key:
                row["condition"], row["reason"] = "missing_business_key", "业务编号为空"
                add_row(row)
                continue

            # 同一批重复提交：直接沿用首次结果，不再调签发。
            if key in seen:
                first = seen[key]
                row["duplicate_of_line"] = first["line_no"]
                if first["status"] == "rejected":
                    row["condition"] = first["condition"]
                    row["reason"] = f"与第 {first['line_no']} 行业务编号重复，沿用其判定：{first['reason']}"
                else:
                    row["status"] = "replayed"
                    row["credential_id"] = first["credential_id"]
                    row["reason"] = f"与第 {first['line_no']} 行业务编号重复，沿用首次结果"
                add_row(row, register_key=False)
                continue

            missing = [f["name"] for f in fields if f["required"] and not claims.get(f["name"])]
            if missing:
                row["condition"] = "missing_fields"
                row["reason"] = f"缺少必填声明：{', '.join(missing)}"
                add_row(row)
                continue

            existing = self.conn.execute(
                "SELECT id FROM credentials WHERE template_id=? AND holder_id=? AND idempotency_key=?",
                (template_id, holder, key),
            ).fetchone()
            try:
                credential = self.service.issue(actor, "issuer", template_id, holder, claims, key)
            except ApiError as exc:
                # 错误行不落任何凭证记录，只保留批次逐行结果。
                row["condition"] = self._condition(exc)
                row["reason"] = exc.message
                add_row(row)
                continue

            row["credential_id"] = credential["id"]
            if existing:
                row["status"] = "replayed"
                row["reason"] = f"凭证 #{credential['id']} 此前已签发，沿用原单"
            else:
                row["status"] = "issued"
            add_row(row)

        batch = {
            "id": uuid.uuid4().hex,
            "issuer": actor,
            "template_id": template_id,
            "created_at": iso(),
            "summary": {
                "total": len(rows),
                "issued": counts["issued"],
                "replayed": counts["replayed"],
                "rejected": counts["rejected"],
            },
        }
        self.store.audit(
            actor,
            "batch.submit",
            "issuance_batch",
            batch["id"],
            {"template_id": template_id, **batch["summary"]},
        )
        self.store.save_batch(batch, rows)
        return {**batch, "rows": rows}

    def get(self, actor: str | None, role: str | None, batch_id: str) -> dict:
        actor = self.service._required_actor(actor, role, "issuer")
        record = self.store.get_batch(batch_id)
        if not record:
            raise ApiError(404, "批次不存在")
        if record["issuer"] != actor:
            raise ApiError(403, "只能查看自己的批次")
        return self._batch_dict(record, self.store.get_batch_rows(batch_id))

    def list_batches(self, actor: str | None, role: str | None) -> dict:
        actor = self.service._required_actor(actor, role, "issuer")
        return {"batches": [self._summary_dict(row) for row in self.store.list_batches(actor)]}

    @staticmethod
    def _summary_dict(row) -> dict:
        return {
            "id": row["id"],
            "issuer": row["issuer"],
            "template_id": row["template_id"],
            "created_at": row["created_at"],
            "total": row["total"],
            "issued": row["issued_count"],
            "replayed": row["replayed_count"],
            "rejected": row["rejected_count"],
        }

    def _batch_dict(self, record, rows) -> dict:
        result = self._summary_dict(record)
        result["rows"] = []
        for row in rows:
            result["rows"].append(
                {
                    "line_no": row["line_no"],
                    "holder_id": row["holder_id"],
                    "business_key": row["business_key"],
                    "claims": json.loads(row["claims_json"]) if row["claims_json"] else None,
                    "status": row["status"],
                    "condition": row["condition_code"],
                    "reason": row["reason"],
                    "credential_id": row["credential_id"],
                    "duplicate_of_line": row["duplicate_of_line"],
                }
            )
        return result
