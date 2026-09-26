import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, BatchService, CredentialService, Store, parse_roster_text


class BatchServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "test.db")
        self.service = CredentialService(self.store)
        self.batch = BatchService(self.store, self.service)
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}],
            365,
        )
        self.tid = self.template["id"]

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def submit(self, text, actor="issuer-a", role="issuer", template_id=None):
        return self.batch.submit(actor, role, self.tid if template_id is None else template_id, text)

    def test_mixed_rows_issued_reused_and_blocked(self):
        roster = "\n".join([
            "业务编号\t持有人\tname\tprogram\tdegree",
            "BIZ-1\tS001\t张三\t计算机\t工学学士",
            "BIZ-1\tS001\t张三\t计算机\t工学学士",
            "BIZ-2\tS002\t李四\t\t",
            "BIZ-3\tS003\t王五\t数学\t理学学士",
        ])
        result = self.submit(roster)
        self.assertEqual(4, result["total_rows"])
        self.assertEqual(2, result["issued_count"])
        self.assertEqual(1, result["reused_count"])
        self.assertEqual(1, result["blocked_count"])
        outcomes = {item["line_no"]: item for item in result["items"]}
        self.assertEqual("issued", outcomes[2]["outcome"])
        self.assertIsNotNone(outcomes[2]["credential_id"])
        self.assertEqual("reused", outcomes[3]["outcome"])
        self.assertEqual(outcomes[2]["credential_id"], outcomes[3]["credential_id"])
        self.assertIn("第 2 行", outcomes[3]["reason"])
        self.assertEqual("blocked", outcomes[4]["outcome"])
        self.assertIn("声明不完整", outcomes[4]["reason"])
        self.assertIsNone(outcomes[4]["credential_id"])
        # 错误行不落凭证记录
        self.assertIsNone(self.store.conn.execute(
            "SELECT id FROM credentials WHERE holder_id='S002'").fetchone())
        # 持久化后可复查总数与逐行结果
        again = self.batch.get_batch("issuer-a", "issuer", result["id"])
        self.assertEqual(result["total_rows"], again["total_rows"])
        self.assertEqual([i["line_no"] for i in result["items"]], [i["line_no"] for i in again["items"]])

    def test_same_ref_different_holder_is_blocked(self):
        roster = "\n".join([
            "业务编号,持有人,name,program",
            "BIZ-1,S001,张三,计算机",
            "BIZ-1,S009,冒名,计算机",
        ])
        result = self.submit(roster)
        self.assertEqual("issued", result["items"][0]["outcome"])
        self.assertEqual("blocked", result["items"][1]["outcome"])
        self.assertIn("持有人不一致", result["items"][1]["reason"])

    def test_resubmit_same_roster_reuses_original(self):
        roster = "业务编号\t持有人\tname\tprogram\nBIZ-7\tS007\t钱七\t物理\n"
        first = self.submit(roster)
        second = self.submit(roster)
        self.assertEqual("issued", first["items"][0]["outcome"])
        self.assertEqual("reused", second["items"][0]["outcome"])
        self.assertIn("沿用此前", second["items"][0]["reason"])
        self.assertEqual(first["items"][0]["credential_id"], second["items"][0]["credential_id"])
        self.assertEqual(1, self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0])
        self.assertEqual(2, self.store.conn.execute("SELECT COUNT(*) FROM batch_issuances").fetchone()[0])

    def test_missing_required_columns_and_unknown_fields(self):
        # 缺少必填字段列：所有行因声明不完整被挡，批次仍记录
        result = self.submit("业务编号\t持有人\tname\nBIZ-1\tS001\t张三\n")
        self.assertEqual(1, result["blocked_count"])
        self.assertIn("缺少=['program']", result["items"][0]["reason"])
        # 表头里有模板外字段列：整列对应行被挡，不产生凭证
        result = self.submit("业务编号\t持有人\tname\tprogram\thobby\nBIZ-1\tS001\t张三\t计算机\t足球\n")
        self.assertEqual("blocked", result["items"][0]["outcome"])
        self.assertIn("hobby", result["items"][0]["reason"])

    def test_roster_parse_errors(self):
        headers, rows = parse_roster_text("")
        self.assertEqual([], headers)
        self.assertEqual("名单为空", rows[0]["_fatal"])
        headers, rows = parse_roster_text("持有人\tname\nS001\t张三")
        self.assertEqual("表头必须包含「业务编号」和「持有人」两列", rows[0]["_fatal"])
        headers, rows = parse_roster_text("业务编号\t持有人\tname\nBIZ-1\tS001\t张三")
        self.assertEqual(["业务编号", "持有人", "name"], headers)
        self.assertEqual("张三", rows[0]["name"])
        headers, rows = parse_roster_text("业务编号,持有人,name\n\nBIZ-2,S002,李四")
        self.assertEqual(1, len(rows))  # 空行跳过，行号按物理行计数
        self.assertEqual(3, rows[0]["line_no"])

    def test_fatal_roster_rejects_whole_batch_without_record(self):
        with self.assertRaises(ApiError) as ctx:
            self.submit("持有人\tname\nS001\t张三")
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.submit("   \n ")
        self.assertEqual(0, self.store.conn.execute("SELECT COUNT(*) FROM batch_issuances").fetchone()[0])
        self.assertEqual(0, self.store.conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0])

    def test_ragged_row_is_recorded_as_blocked(self):
        roster = "业务编号\t持有人\tname\tprogram\nBIZ-1\tS001\t张三\n"
        result = self.submit(roster)
        self.assertEqual("blocked", result["items"][0]["outcome"])
        self.assertIn("列数", result["items"][0]["reason"])

    def test_permissions_and_listing(self):
        self.submit("业务编号\t持有人\tname\tprogram\nBIZ-1\tS001\t张三\t计算机\n")
        with self.assertRaises(ApiError) as ctx:
            self.batch.submit("issuer-b", "issuer", self.tid, "业务编号\t持有人\n")
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.batch.list_batches(None, "issuer")
        listing = self.batch.list_batches("issuer-a", "issuer")
        self.assertEqual(1, listing["total"])
        self.assertEqual("degree", listing["batches"][0]["template_code"])
        with self.assertRaises(ApiError) as ctx:
            self.batch.get_batch("issuer-b", "issuer", listing["batches"][0]["id"])
        self.assertEqual(403, ctx.exception.status)

    def test_single_issue_still_interoperable(self):
        # 单张签发后，批量提交相同业务编号沿用原单
        one = self.service.issue("issuer-a", "issuer", self.tid, "S100",
                                 {"name": "赵十", "program": "化学"}, "BIZ-100")
        result = self.submit("业务编号\t持有人\tname\tprogram\nBIZ-100\tS100\t赵十\t化学\n")
        self.assertEqual("reused", result["items"][0]["outcome"])
        self.assertEqual(one["id"], result["items"][0]["credential_id"])
        # 批内首行被挡时，重复行沿用该判定而非再试签发
        blocked_then_dup = self.submit("\n".join([
            "业务编号\t持有人\tname\tprogram",
            "BIZ-200\tS200\t缺专业\t",
            "BIZ-200\tS200\t缺专业\t",
        ]))
        self.assertEqual(["blocked", "blocked"], [i["outcome"] for i in blocked_then_dup["items"]])
        self.assertIn("第 2 行", blocked_then_dup["items"][1]["reason"])


if __name__ == "__main__":
    unittest.main()
