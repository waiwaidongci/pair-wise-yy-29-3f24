#!/usr/bin/env python3
"""Minimal standards-library digital credential service for local evaluation."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DB_PATH = Path(__file__).with_name("data.db")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return now()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Store:
    def __init__(self, path: str | os.PathLike[str] = DB_PATH):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS key_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              secret_hex TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','retired')),
              created_at TEXT NOT NULL,
              retired_at TEXT,
              UNIQUE(issuer, version)
            );
            CREATE TABLE IF NOT EXISTS templates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              code TEXT NOT NULL,
              name TEXT NOT NULL,
              fields_json TEXT NOT NULL,
              validity_days INTEGER NOT NULL CHECK(validity_days BETWEEN 1 AND 3650),
              status TEXT NOT NULL CHECK(status IN ('active','disabled')),
              created_at TEXT NOT NULL,
              UNIQUE(issuer, code)
            );
            CREATE TABLE IF NOT EXISTS credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              issuer TEXT NOT NULL,
              holder_id TEXT NOT NULL,
              claims_json TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              valid_until TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('active','revoked','disputed')),
              key_version INTEGER NOT NULL,
              idempotency_key TEXT NOT NULL,
              revocation_reason TEXT,
              revocation_effective_at TEXT,
              UNIQUE(template_id, holder_id, idempotency_key)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_live_credential
              ON credentials(template_id, holder_id)
              WHERE status IN ('active','disputed');
            CREATE TABLE IF NOT EXISTS disputes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              credential_id INTEGER NOT NULL REFERENCES credentials(id),
              raised_by TEXT NOT NULL,
              reason TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('open','upheld','rejected')),
              resolution TEXT,
              created_at TEXT NOT NULL,
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              details_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS batch_issuances (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              template_id INTEGER NOT NULL REFERENCES templates(id),
              total_rows INTEGER NOT NULL,
              issued_count INTEGER NOT NULL,
              reused_count INTEGER NOT NULL,
              blocked_count INTEGER NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS batch_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              batch_id INTEGER NOT NULL REFERENCES batch_issuances(id),
              line_no INTEGER NOT NULL,
              ref TEXT,
              holder_id TEXT,
              outcome TEXT NOT NULL CHECK(outcome IN ('issued','reused','blocked')),
              credential_id INTEGER,
              reason TEXT,
              UNIQUE(batch_id, line_no)
            );
            CREATE INDEX IF NOT EXISTS idx_batch_items_batch ON batch_items(batch_id);
            """
        )
        self.conn.commit()

    def audit(self, actor: str, action: str, entity_type: str, entity_id: object, details: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log(at,actor,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?,?)",
            (iso(), actor, action, entity_type, str(entity_id), json.dumps(details, ensure_ascii=False)),
        )

    def save_batch(self, actor: str, template_id: int, rows: list[dict]) -> int:
        """批次、逐行结果与审计在同一事务落库；错误行只进批次行表，不产生凭证。"""
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO batch_issuances(issuer,template_id,total_rows,issued_count,reused_count,blocked_count,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    actor,
                    template_id,
                    len(rows),
                    sum(1 for r in rows if r["outcome"] == "issued"),
                    sum(1 for r in rows if r["outcome"] == "reused"),
                    sum(1 for r in rows if r["outcome"] == "blocked"),
                    iso(),
                ),
            )
            batch_id = int(cur.lastrowid)
            self.conn.executemany(
                """INSERT INTO batch_items(batch_id,line_no,ref,holder_id,outcome,credential_id,reason)
                   VALUES(?,?,?,?,?,?,?)""",
                [
                    (
                        batch_id,
                        r["line_no"],
                        r.get("ref"),
                        r.get("holder_id"),
                        r["outcome"],
                        r.get("credential_id"),
                        r.get("reason"),
                    )
                    for r in rows
                ],
            )
            self.audit(actor, "batch.issue", "batch", batch_id, {
                "template_id": template_id,
                "total": len(rows),
                "issued": sum(1 for r in rows if r["outcome"] == "issued"),
                "reused": sum(1 for r in rows if r["outcome"] == "reused"),
                "blocked": sum(1 for r in rows if r["outcome"] == "blocked"),
            })
        return batch_id

    def list_batches(self, issuer: str, limit: int = 100) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT b.*, t.code AS template_code, t.name AS template_name
               FROM batch_issuances b JOIN templates t ON t.id=b.template_id
               WHERE b.issuer=? ORDER BY b.id DESC LIMIT ?""",
            (issuer, limit),
        ).fetchall()

    def get_batch(self, batch_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            """SELECT b.*, t.code AS template_code, t.name AS template_name
               FROM batch_issuances b JOIN templates t ON t.id=b.template_id
               WHERE b.id=?""",
            (batch_id,),
        ).fetchone()

    def get_batch_items(self, batch_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM batch_items WHERE batch_id=? ORDER BY line_no", (batch_id,)
        ).fetchall()

    def close(self) -> None:
        self.conn.close()


class CredentialService:
    """Credential issuance and verification with small, explicit trust boundaries."""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn

    @staticmethod
    def _required_actor(actor: str | None, role: str | None, expected: str) -> str:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != expected:
            raise ApiError(403, f"需要角色 {expected}")
        return actor

    def _row(self, table: str, identity: int) -> sqlite3.Row:
        row = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (identity,)).fetchone()
        if not row:
            raise ApiError(404, "对象不存在")
        return row

    def _active_key(self, issuer: str) -> sqlite3.Row:
        row = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1", (issuer,)
        ).fetchone()
        if not row:
            raise ApiError(409, "签发方尚未初始化密钥")
        return row

    def rotate_key(self, actor: str | None, role: str | None, issuer: str) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if actor != issuer:
            raise ApiError(403, "只能轮换自己的密钥")
        with self.conn:
            old = self.conn.execute("SELECT * FROM key_versions WHERE issuer=? AND status='active'", (issuer,)).fetchone()
            version = 1
            if old:
                version = int(old["version"]) + 1
                self.conn.execute("UPDATE key_versions SET status='retired', retired_at=? WHERE id=?", (iso(), old["id"]))
            secret_hex = secrets.token_hex(32)
            cur = self.conn.execute(
                "INSERT INTO key_versions(issuer,version,secret_hex,status,created_at) VALUES(?,?,?,'active',?)",
                (issuer, version, secret_hex, iso()),
            )
            self.store.audit(actor, "key.rotate", "key_version", cur.lastrowid, {"version": version, "retired_previous": bool(old)})
        return {"issuer": issuer, "version": version, "status": "active", "public_fingerprint": hashlib.sha256(secret_hex.encode()).hexdigest()[:20]}

    def create_template(self, actor: str | None, role: str | None, code: str, name: str, fields: list[dict], validity_days: int) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not code.strip() or not name.strip():
            raise ApiError(400, "模板代号和名称不能为空")
        field_names: set[str] = set()
        normalized = []
        for field in fields:
            field_name = str(field.get("name", "")).strip()
            if not field_name or field_name in field_names:
                raise ApiError(400, "模板字段为空或重复")
            field_names.add(field_name)
            normalized.append({"name": field_name, "required": bool(field.get("required", False))})
        if not normalized:
            raise ApiError(400, "模板至少需要一个字段")
        try:
            with self.conn:
                cur = self.conn.execute(
                    "INSERT INTO templates(issuer,code,name,fields_json,validity_days,status,created_at) VALUES(?,?,?,?,?,'active',?)",
                    (actor, code, name, json.dumps(normalized, ensure_ascii=False), int(validity_days), iso()),
                )
                self.store.audit(actor, "template.create", "template", cur.lastrowid, {"code": code, "fields": normalized})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "同一签发方不能重复使用模板代号") from exc
        return {"id": cur.lastrowid, "issuer": actor, "code": code, "name": name, "fields": normalized, "validity_days": validity_days, "status": "active"}

    def issue(self, actor: str | None, role: str | None, template_id: int, holder_id: str, claims: dict, idempotency_key: str, valid_until: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        if not holder_id.strip() or not idempotency_key.strip():
            raise ApiError(400, "持有人和幂等键不能为空")
        template = self._row("templates", template_id)
        if template["issuer"] != actor:
            raise ApiError(403, "不能使用其他签发方的模板")
        if template["status"] != "active":
            raise ApiError(409, "模板已停用")
        existing = self.conn.execute(
            "SELECT * FROM credentials WHERE template_id=? AND holder_id=? AND idempotency_key=?",
            (template_id, holder_id, idempotency_key),
        ).fetchone()
        if existing:
            return self._credential_dict(existing)
        fields = json.loads(template["fields_json"])
        missing = [f["name"] for f in fields if f["required"] and not str(claims.get(f["name"], "")).strip()]
        unknown = sorted(set(claims) - {f["name"] for f in fields})
        if missing or unknown:
            raise ApiError(400, f"声明不完整，缺少={missing}，未知字段={unknown}")
        live = self.conn.execute(
            "SELECT id FROM credentials WHERE template_id=? AND holder_id=? AND status IN ('active','disputed')",
            (template_id, holder_id),
        ).fetchone()
        if live:
            raise ApiError(409, "该持有人已有有效的同模板凭证；重复提交应使用相同幂等键")
        issued = now()
        expiration = parse_time(valid_until) if valid_until else issued + timedelta(days=int(template["validity_days"]))
        if expiration <= issued:
            raise ApiError(400, "有效期必须晚于签发时间")
        key = self._active_key(actor)
        try:
            with self.conn:
                cur = self.conn.execute(
                    """INSERT INTO credentials(template_id,issuer,holder_id,claims_json,issued_at,valid_until,status,key_version,idempotency_key)
                       VALUES(?,?,?,?,?,?, 'active',?,?)""",
                    (template_id, actor, holder_id, json.dumps(claims, ensure_ascii=False), iso(issued), iso(expiration), key["version"], idempotency_key),
                )
                self.store.audit(actor, "credential.issue", "credential", cur.lastrowid, {"holder_id": holder_id, "template_id": template_id, "key_version": key["version"]})
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "并发签发冲突，请用相同幂等键重试") from exc
        return self._credential_dict(self._row("credentials", cur.lastrowid))

    def revoke(self, actor: str | None, role: str | None, credential_id: int, reason: str, effective_at: str | None = None) -> dict:
        actor = self._required_actor(actor, role, "issuer")
        credential = self._row("credentials", credential_id)
        if credential["issuer"] != actor:
            raise ApiError(403, "只能撤销本机构签发的凭证")
        if credential["status"] == "revoked":
            if credential["revocation_reason"] == reason:
                return self._credential_dict(credential)
            raise ApiError(409, "凭证已经撤销")
        effective = parse_time(effective_at) if effective_at else now()
        with self.conn:
            self.conn.execute(
                "UPDATE credentials SET status='revoked',revocation_reason=?,revocation_effective_at=? WHERE id=?",
                (reason, iso(effective), credential_id),
            )
            self.store.audit(actor, "credential.revoke", "credential", credential_id, {"reason": reason, "effective_at": iso(effective)})
        return self._credential_dict(self._row("credentials", credential_id))

    def dispute(self, actor: str | None, role: str | None, credential_id: int, reason: str) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "只能对自己的凭证提出争议")
        if credential["status"] != "revoked":
            raise ApiError(409, "只有已撤销凭证可以提出争议")
        open_dispute = self.conn.execute("SELECT id FROM disputes WHERE credential_id=? AND status='open'", (credential_id,)).fetchone()
        if open_dispute:
            raise ApiError(409, "已有待处理争议")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO disputes(credential_id,raised_by,reason,status,created_at) VALUES(?,?,?,'open',?)",
                (credential_id, actor, reason, iso()),
            )
            self.conn.execute("UPDATE credentials SET status='disputed' WHERE id=?", (credential_id,))
            self.store.audit(actor, "dispute.open", "credential", credential_id, {"dispute_id": cur.lastrowid, "reason": reason})
        return {"id": cur.lastrowid, "credential_id": credential_id, "status": "open"}

    def resolve_dispute(self, actor: str | None, role: str | None, dispute_id: int, decision: str, resolution: str) -> dict:
        actor = self._required_actor(actor, role, "regulator")
        if decision not in {"uphold", "reject"}:
            raise ApiError(400, "决定只能是 uphold 或 reject")
        dispute = self._row("disputes", dispute_id)
        if dispute["status"] != "open":
            raise ApiError(409, "争议已经处理")
        credential = self._row("credentials", dispute["credential_id"])
        if credential["status"] != "disputed":
            raise ApiError(409, "凭证状态与争议不一致")
        new_status = "revoked" if decision == "uphold" else "active"
        dispute_status = "upheld" if decision == "uphold" else "rejected"
        with self.conn:
            self.conn.execute("UPDATE disputes SET status=?,resolution=?,resolved_at=? WHERE id=?", (dispute_status, resolution, iso(), dispute_id))
            self.conn.execute("UPDATE credentials SET status=? WHERE id=?", (new_status, credential["id"]))
            self.store.audit(actor, "dispute.resolve", "dispute", dispute_id, {"decision": decision, "credential_status": new_status})
        return {"id": dispute_id, "status": decision, "credential_status": new_status, "resolution": resolution}

    def present(self, actor: str | None, role: str | None, credential_id: int, disclosed_fields: list[str] | None) -> dict:
        actor = self._required_actor(actor, role, "holder")
        credential = self._row("credentials", credential_id)
        if credential["holder_id"] != actor:
            raise ApiError(403, "不能出示他人的凭证")
        template = self._row("templates", credential["template_id"])
        allowed = [field["name"] for field in json.loads(template["fields_json"])]
        disclosed = disclosed_fields if disclosed_fields is not None else allowed
        if len(disclosed) != len(set(disclosed)) or any(name not in allowed for name in disclosed):
            raise ApiError(400, "披露字段不在模板中或重复")
        claims = json.loads(credential["claims_json"])
        visible = {name: claims[name] for name in disclosed}
        payload = {
            "credential_id": credential["id"],
            "template_id": credential["template_id"],
            "issuer": credential["issuer"],
            "holder_id": credential["holder_id"],
            "claims": visible,
            "valid_until": credential["valid_until"],
            "key_version": credential["key_version"],
        }
        key = self.conn.execute(
            "SELECT secret_hex FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], credential["key_version"])
        ).fetchone()
        signature = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        token = base64.urlsafe_b64encode(canonical({"payload": payload, "signature": signature})).decode().rstrip("=")
        self.store.audit(actor, "credential.present", "credential", credential_id, {"disclosed_fields": disclosed})
        self.conn.commit()
        return {"token": token, "payload": payload, "signature": signature, "disclosed_fields": disclosed}

    def verify(self, token: str, at: str | None = None, online: bool = True) -> dict:
        if not token:
            raise ApiError(400, "缺少凭证令牌")
        try:
            padded = token + "=" * (-len(token) % 4)
            envelope = json.loads(base64.urlsafe_b64decode(padded.encode()))
            payload = envelope["payload"]
            supplied_signature = envelope["signature"]
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(400, "凭证令牌格式错误") from exc
        credential = self._row("credentials", int(payload.get("credential_id", 0)))
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (credential["issuer"], credential["key_version"])
        ).fetchone()
        if not key:
            raise ApiError(409, "无法找到签发密钥版本")
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(supplied_signature)):
            raise ApiError(400, "凭证签名无效")
        check_at = parse_time(at)
        expiration = parse_time(credential["valid_until"])
        result = {"valid": True, "status": "valid", "key_retired": key["status"] == "retired", "claims": payload.get("claims", {})}
        if check_at >= expiration:
            result.update(valid=False, status="expired", reason="凭证已过期")
        elif credential["status"] == "disputed":
            result.update(valid=False, status="disputed", reason="撤销决定正在争议复核")
        elif credential["status"] == "revoked":
            effective = parse_time(credential["revocation_effective_at"])
            if check_at >= effective:
                result.update(valid=False, status="revoked", reason=credential["revocation_reason"])
            else:
                result.update(status="valid_until_revocation", revocation_starts_at=credential["revocation_effective_at"])
        if not online:
            result["offline"] = True
            result["revocation_freshness"] = "needs_online_check"
            if result["valid"]:
                result["status"] = "valid_offline"
        self.conn.commit()
        return result

    def _credential_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "template_id": row["template_id"], "issuer": row["issuer"], "holder_id": row["holder_id"],
            "claims": json.loads(row["claims_json"]), "issued_at": row["issued_at"], "valid_until": row["valid_until"],
            "status": row["status"], "key_version": row["key_version"], "revocation_reason": row["revocation_reason"],
            "revocation_effective_at": row["revocation_effective_at"],
        }

    def state(self) -> dict:
        credentials = [self._credential_dict(row) for row in self.conn.execute("SELECT * FROM credentials ORDER BY id DESC")]
        templates = [dict(row) for row in self.conn.execute("SELECT id,issuer,code,name,fields_json,status,validity_days FROM templates ORDER BY id DESC")]
        for template in templates:
            template["fields"] = json.loads(template.pop("fields_json"))
        audits = [dict(row) for row in self.conn.execute("SELECT at,actor,action,entity_type,entity_id,details_json FROM audit_log ORDER BY id DESC LIMIT 30")]
        return {"templates": templates, "credentials": credentials, "audits": audits}

    def seed(self) -> None:
        if not self.conn.execute("SELECT id FROM key_versions LIMIT 1").fetchone():
            self.rotate_key("issuer-demo", "issuer", "issuer-demo")
        if not self.conn.execute("SELECT id FROM templates LIMIT 1").fetchone():
            self.create_template("issuer-demo", "issuer", "student-v1", "学生身份", [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}], 365)


def parse_roster_text(text: str) -> tuple[list[str], list[dict]]:
    """解析按模板粘贴的名单：首行表头（业务编号/持有人/声明字段），制表符或逗号分隔。

    结构问题（空名单、缺少业务编号或持有人列）以带 _fatal 的行返回，
    由批次判定层整批拒绝；列数不一致等记录级问题带 _error，记为挡住行；空行直接跳过。
    """
    raw_lines = [line for line in (text or "").splitlines()]
    non_empty = [line for line in raw_lines if line.strip()]
    if not non_empty:
        return [], [{"line_no": 1, "_fatal": "名单为空"}]
    header_line = non_empty[0]
    delimiter = "\t" if "\t" in header_line else ","

    def split(line: str) -> list[str]:
        return [cell.strip() for cell in next(csv.reader(io.StringIO(line), delimiter=delimiter))]

    headers = split(header_line)
    if "业务编号" not in headers or "持有人" not in headers:
        return headers, [{"line_no": 1, "_fatal": "表头必须包含「业务编号」和「持有人」两列"}]
    rows: list[dict] = []
    line_no = 1
    for line in raw_lines[1:]:
        line_no += 1
        if not line.strip():
            continue
        cells = split(line)
        if len(cells) != len(headers):
            rows.append({"line_no": line_no, "_error": f"列数为 {len(cells)}，与表头 {len(headers)} 列不一致"})
            continue
        rows.append({"line_no": line_no, **dict(zip(headers, cells))})
    return headers, rows


class BatchService:
    """批量签发：只负责逐行判定与批次记录，单张签发仍由 CredentialService.issue 承担。"""

    def __init__(self, store: Store, credentials: CredentialService):
        self.store = store
        self.conn = store.conn
        self.credentials = credentials

    @staticmethod
    def _block(line_no: int, ref: str | None, holder: str | None, reason: str) -> dict:
        return {"line_no": line_no, "ref": ref or None, "holder_id": holder or None,
                "outcome": "blocked", "credential_id": None, "reason": reason}

    def submit(self, actor: str | None, role: str | None, template_id_raw: object, text: str) -> dict:
        actor = CredentialService._required_actor(actor, role, "issuer")
        try:
            template_id = int(template_id_raw)
        except (TypeError, ValueError) as exc:
            raise ApiError(400, "模板编号无效") from exc
        template = self.credentials._row("templates", template_id)
        if template["issuer"] != actor:
            raise ApiError(403, "不能使用其他签发方的模板")
        if template["status"] != "active":
            raise ApiError(409, "模板已停用")
        field_names = [f["name"] for f in json.loads(template["fields_json"])]
        headers, parsed = parse_roster_text(text)
        extra_headers = [h for h in headers if h not in ("业务编号", "持有人", *field_names)]

        fatal = next((r["_fatal"] for r in parsed if r.get("_fatal")), None)
        if fatal:
            raise ApiError(400, f"名单格式问题：{fatal}")

        rows: list[dict] = []
        first_by_ref: dict[str, dict] = {}
        for row in parsed:
            decided = self._decide_row(row, field_names, extra_headers, first_by_ref, template, actor)
            rows.append(decided)
            ref = decided.get("ref")
            if ref and ref not in first_by_ref:
                first_by_ref[ref] = decided

        batch_id = self.store.save_batch(actor, template_id, rows)
        return self.get_batch(actor, role, batch_id)

    def _decide_row(
        self,
        row: dict,
        field_names: list[str],
        extra_headers: list[str],
        first_by_ref: dict[str, dict],
        template: sqlite3.Row,
        actor: str,
    ) -> dict:
        line_no = int(row["line_no"])
        if row.get("_error"):
            return self._block(line_no, None, None, f"名单格式问题：{row['_error']}")
        ref = str(row.get("业务编号", "")).strip()
        holder = str(row.get("持有人", "")).strip()
        if not ref:
            return self._block(line_no, None, holder, "缺少业务编号")
        if not holder:
            return self._block(line_no, ref, None, "缺少持有人")
        if extra_headers:
            return self._block(line_no, ref, holder, f"存在模板外字段列：{extra_headers}")

        first = first_by_ref.get(ref)
        if first is not None:
            if first.get("holder_id") != holder:
                return self._block(line_no, ref, holder, "业务编号在本批重复，但持有人不一致")
            if first["outcome"] == "blocked":
                return self._block(line_no, ref, holder, f"与本批第 {first['line_no']} 行重复，该行被挡：{first['reason']}")
            return {
                "line_no": line_no, "ref": ref, "holder_id": holder,
                "outcome": "reused", "credential_id": first["credential_id"],
                "reason": f"沿用本批第 {first['line_no']} 行的签发结果",
            }

        claims = {name: str(row.get(name, "")).strip() for name in field_names}
        # issue 命中幂等时返回的就是原单，先查是否早已存在以区分“签出”和“沿用原单”
        existed = self.conn.execute(
            "SELECT id FROM credentials WHERE template_id=? AND holder_id=? AND idempotency_key=?",
            (template["id"], holder, ref),
        ).fetchone()
        try:
            credential = self.credentials.issue(
                actor, "issuer", int(template["id"]), holder, claims, ref
            )
        except ApiError as exc:
            return self._block(line_no, ref, holder, exc.message)
        if existed:
            return {
                "line_no": line_no, "ref": ref, "holder_id": holder,
                "outcome": "reused", "credential_id": credential["id"],
                "reason": "沿用此前相同业务编号的原单",
            }
        return {
            "line_no": line_no, "ref": ref, "holder_id": holder,
            "outcome": "issued", "credential_id": credential["id"], "reason": None,
        }

    def list_batches(self, actor: str | None, role: str | None) -> dict:
        actor = CredentialService._required_actor(actor, role, "issuer")
        batches = [self._batch_summary(row) for row in self.store.list_batches(actor)]
        return {"batches": batches, "total": len(batches)}

    def get_batch(self, actor: str | None, role: str | None, batch_id_raw: object) -> dict:
        actor = CredentialService._required_actor(actor, role, "issuer")
        try:
            batch_id = int(batch_id_raw)
        except (TypeError, ValueError) as exc:
            raise ApiError(400, "批次编号无效") from exc
        batch = self.store.get_batch(batch_id)
        if not batch:
            raise ApiError(404, "批次不存在")
        if batch["issuer"] != actor:
            raise ApiError(403, "只能查看本机构的批次")
        items = [dict(row) for row in self.store.get_batch_items(batch_id)]
        result = self._batch_summary(batch)
        result["items"] = items
        return result

    @staticmethod
    def _batch_summary(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "issuer": row["issuer"],
            "template_id": row["template_id"],
            "template_code": row["template_code"],
            "template_name": row["template_name"],
            "total_rows": row["total_rows"],
            "issued_count": row["issued_count"],
            "reused_count": row["reused_count"],
            "blocked_count": row["blocked_count"],
            "created_at": row["created_at"],
        }


class Handler(BaseHTTPRequestHandler):
    service: CredentialService
    batch: BatchService

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ApiError(400, "JSON 请求体无效") from exc

    def _parts(self) -> list[str]:
        return [part for part in urlparse(self.path).path.strip("/").split("/") if part]

    def do_GET(self) -> None:
        try:
            parts = self._parts()
            actor, role = self.headers.get("X-Actor"), self.headers.get("X-Role")
            if parts == ["health"] or parts == ["api", "health"]:
                return self._json(200, {"status": "ok"})
            if parts == ["api", "state"]:
                return self._json(200, self.service.state())
            if parts == ["api", "batches"]:
                return self._json(200, self.batch.list_batches(actor, role))
            if len(parts) == 3 and parts[:2] == ["api", "batches"]:
                return self._json(200, self.batch.get_batch(actor, role, parts[2]))
            if not parts:
                page = (Path(__file__).parent / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
                return
            raise ApiError(404, "接口不存在")
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except Exception as exc:
            self._json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            parts = self._parts()
            body = self._body()
            actor, role = self.headers.get("X-Actor"), self.headers.get("X-Role")
            if parts == ["api", "keys", "rotate"]:
                result = self.service.rotate_key(actor, role, body.get("issuer", actor or ""))
            elif parts == ["api", "templates"]:
                result = self.service.create_template(actor, role, body.get("code", ""), body.get("name", ""), body.get("fields", []), int(body.get("validity_days", 1)))
            elif parts == ["api", "credentials"]:
                result = self.service.issue(actor, role, int(body.get("template_id", 0)), body.get("holder_id", ""), body.get("claims", {}), body.get("idempotency_key", ""), body.get("valid_until"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "revoke":
                result = self.service.revoke(actor, role, int(parts[2]), body.get("reason", ""), body.get("effective_at"))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "dispute":
                result = self.service.dispute(actor, role, int(parts[2]), body.get("reason", ""))
            elif len(parts) == 4 and parts[:2] == ["api", "credentials"] and parts[3] == "present":
                result = self.service.present(actor, role, int(parts[2]), body.get("disclosed_fields"))
            elif len(parts) == 4 and parts[:2] == ["api", "disputes"] and parts[3] == "resolve":
                result = self.service.resolve_dispute(actor, role, int(parts[2]), body.get("decision", ""), body.get("resolution", ""))
            elif parts == ["api", "verify"]:
                result = self.service.verify(body.get("token", ""), body.get("at"), bool(body.get("online", True)))
            elif parts == ["api", "batches"]:
                result = self.batch.submit(actor, role, body.get("template_id"), body.get("roster", ""))
            else:
                raise ApiError(404, "接口不存在")
            self._json(200, result)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": str(exc)})


def run(port: int, db_path: str, seed: bool) -> None:
    store = Store(db_path)
    service = CredentialService(store)
    if seed:
        service.seed()
    Handler.service = service
    Handler.batch = BatchService(store, service)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"digital credentials listening on http://127.0.0.1:{port}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8211)
    parser.add_argument("--db", default=str(DB_PATH))
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    if args.init:
        Store(args.db).close()
    if not any((args.seed, not args.init)):
        return
    run(args.port, args.db, args.seed)


if __name__ == "__main__":
    main()
