import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store
from batch import BatchService, parse_batch_text


class BatchIssueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.batches = BatchService(self.service)
        self.template = self.service.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "program", "required": True}, {"name": "degree", "required": False}],
            365,
        )["id"]

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def submit(self, text, actor="issuer-a"):
        return self.batches.submit(actor, "issuer", self.template, text)

    def test_mixed_valid_missing_duplicate_and_bad_columns(self):
        text = "\n".join([
            "持有人\tname\tprogram\tdegree\t业务编号",  # 表头应被跳过
            "alice\tAlice\tCS\tBSc\tK-1",              # 正常签发
            "bob\tBob\tSE\t\tK-2",                     # 选填缺失，仍签发
            "carol\tCarol\t\tMSc\tK-3",                # 必填缺失，挡住
            "\tDan\tMath\tPhD\tK-4",                   # 持有人为空
            "erin\tErin\tArt\tBA",                     # 少一列
            "alice\tAlice Dupe\tCS Dupe\tBSc\tK-1",    # 批内重复，沿用首次（凭证与alice一致）
        ])
        result = self.submit(text)
        self.assertEqual(7 - 1, result["summary"]["total"])
        self.assertEqual({"issued": 2, "replayed": 1, "rejected": 3},
                         {k: result["summary"][k] for k in ("issued", "replayed", "rejected")})
        statuses = {r["line_no"]: r for r in result["rows"]}
        self.assertEqual("issued", statuses[2]["status"])
        self.assertEqual("issued", statuses[3]["status"])
        self.assertEqual("missing_fields", statuses[4]["condition"])
        self.assertEqual("missing_holder", statuses[5]["condition"])
        self.assertEqual("bad_columns", statuses[6]["condition"])
        dup = statuses[7]
        self.assertEqual("replayed", dup["status"])
        self.assertEqual(2, dup["duplicate_of_line"])
        self.assertEqual(statuses[2]["credential_id"], dup["credential_id"])

    def test_errors_leave_no_credential_records(self):
        self.submit("carol\tCarol\t\tMSc\tK-3\n\tx\ty\tz\tK-4")
        credentials = self.service.conn.execute("SELECT holder_id FROM credentials").fetchall()
        self.assertEqual([], [r["holder_id"] for r in credentials])

    def test_resubmit_same_batch_text_reuses_original(self):
        text = "alice\tAlice\tCS\tBSc\tK-1"
        first = self.submit(text)
        second = self.submit(text)
        first_id = first["rows"][0]["credential_id"]
        self.assertEqual("issued", first["rows"][0]["status"])
        self.assertEqual("replayed", second["rows"][0]["status"])
        self.assertEqual(first_id, second["rows"][0]["credential_id"])
        self.assertEqual(1, self.service.conn.execute("SELECT COUNT(*) AS c FROM credentials").fetchone()["c"])

    def test_rejected_first_occurrence_is_replayed_as_rejected(self):
        result = self.submit("carol\tCarol\t\tMSc\tK-3\ncarol2\tCarol2\t\tMSc\tK-3")
        self.assertEqual(["rejected", "rejected"], [r["status"] for r in result["rows"]])
        self.assertEqual(1, result["rows"][1]["duplicate_of_line"])
        self.assertEqual("missing_fields", result["rows"][1]["condition"])

    def test_other_issuer_template_forbidden(self):
        with self.assertRaises(ApiError) as ctx:
            self.submit("alice\tAlice\tCS\tBSc\tK-1", actor="issuer-b")
        self.assertEqual(403, ctx.exception.status)

    def test_non_issuer_rejected_and_empty_batch_rejected(self):
        with self.assertRaises(ApiError):
            self.batches.submit("alice", "holder", self.template, "alice\tAlice\tCS\tBSc\tK-1")
        with self.assertRaises(ApiError) as ctx:
            self.batches.submit("issuer-a", "issuer", self.template, "  \n\n")
        self.assertEqual(400, ctx.exception.status)

    def test_batch_get_and_list_are_persisted_per_issuer(self):
        result = self.submit("alice\tAlice\tCS\tBSc\tK-1")
        loaded = self.batches.get("issuer-a", "issuer", result["id"])
        self.assertEqual(result["id"], loaded["id"])
        self.assertEqual("issued", loaded["rows"][0]["status"])
        self.assertEqual("Alice", loaded["rows"][0]["claims"]["name"])
        listing = self.batches.list_batches("issuer-a", "issuer")
        self.assertEqual([result["id"]], [b["id"] for b in listing["batches"]])
        with self.assertRaises(ApiError) as ctx:
            self.batches.get("issuer-b", "issuer", result["id"])
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.batches.get("issuer-a", "issuer", "nope")

    def test_active_credential_with_other_key_is_blocked(self):
        # 先给 dan 用别的业务编号签出一张；同持有人再来不同编号应被规则挡住，不新建凭证。
        self.submit("dan\tDan\tMath\tPhD\tK-10")
        result = self.submit("dan\tDan\tMath\tPhD\tK-11")
        self.assertEqual("rejected", result["rows"][0]["status"])
        self.assertEqual("active_credential_exists", result["rows"][0]["condition"])
        self.assertEqual(1, self.service.conn.execute("SELECT COUNT(*) AS c FROM credentials").fetchone()["c"])

    def test_comma_separated_and_header_detection(self):
        parsed = parse_batch_text("holder,name,program,degree,business_key\nalice,Alice,CS,BSc,K-1")
        self.assertEqual([(2, ["alice", "Alice", "CS", "BSc", "K-1"])], parsed)
        parsed = parse_batch_text("持有人\tname\t业务编号\nx\ta\tK")  # 3列模板才适用表头规则
        # 表头判定只看首尾列名，与中间列数无关
        self.assertEqual([(2, ["x", "a", "K"])], parsed)


if __name__ == "__main__":
    unittest.main()
