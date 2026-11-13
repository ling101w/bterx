"""Local boundary tests for the on-demand native experience reader."""
import copy
import io
import json
import unittest
from unittest.mock import patch

import experience_retrieval as retrieval


REAL_ID = "a" * 24
UNKNOWN_ID = "b" * 24


def row(kind, tool=None, detail=None, is_error=False):
    return {"kind": kind, "tool": tool, "detail": detail if isinstance(detail, str) else json.dumps(detail or {}),
            "summary": "", "is_error": is_error}


def transcript(*, task_id=42, hits=True, answer=None):
    return [row("tool_use", "experience_search", {"task_id": task_id, "query": "authorization"}),
            row("tool_result", "experience_search", {"experiences": [{"id": REAL_ID}] if hits else []}),
            row("result", detail=answer or ("候选经验 " + REAL_ID + " 需要当前任务验证。" if hits else "没有检索到相关经验。"))]


class FakeDatabase:
    def __init__(self, rows=None, enabled=True):
        self.rows = rows if rows is not None else transcript()
        self.enabled = enabled
        self.queries = []

    def query(self, sql):
        self.queries.append(sql)
        if "FROM agents" in sql:
            return [{"id": 1}] if self.enabled else []
        if "FROM conversation_activities" in sql:
            return copy.deepcopy(self.rows)
        raise AssertionError("Unexpected fake database query")


class FakeRuntime:
    cards = {}
    checked_tasks = []
    gets = []

    def __init__(self, database):
        self.database = database

    def task_exists(self, task_id):
        self.checked_tasks.append(task_id)

    def get(self, payload):
        self.gets.append(payload)
        if payload["id"] not in self.cards:
            raise ValueError("Experience unavailable in this task scope")
        return {"experience": copy.deepcopy(self.cards[payload["id"]])}


class FakeAPI:
    def __init__(self, statuses=None):
        self.statuses = statuses or [{"running": False, "items": [{"kind": "result"}]}]
        self.requests = []

    def request(self, path, body=None):
        self.requests.append((path, body))
        if path == "/api/conversations":
            return {"id": 7}
        if path.endswith("/messages?since=0"):
            return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return {}


class FakeClock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def pause(self, seconds):
        self.now += seconds


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        FakeRuntime.cards = {REAL_ID: {
            "id": REAL_ID, "title": "Resource ownership comparison", "category": "authorization",
            "tags": ["authorization"], "status": "candidate", "outcome": "success", "transfer_scope": "generic",
            "applicable_when": "Two controlled identities are available.", "success_criteria": "Independent current evidence.",
            "not_applicable": "An identity prerequisite is missing.", "root_cause": "Ownership was not checked.",
            "steps": ["Compare authorized controlled requests."],
            "attack_chain": [{"step": 1, "prerequisite": "Controlled identity", "action": "Compare responses",
                              "observed_result": "A controlled difference was observed", "evidence_ids": ["activity:123"]}],
            "source_task_id": 999, "evidence": [{"text": "PRIVATE RAW EVIDENCE"}],
            "snapshot_id": "PRIVATE SNAPSHOT", "source_key": "finding:999",
        }}
        FakeRuntime.checked_tasks, FakeRuntime.gets = [], []
        self.runtime_patch = patch.object(retrieval, "Runtime", FakeRuntime)
        self.runtime_patch.start()
        self.addCleanup(self.runtime_patch.stop)

    def test_success_requires_search_and_returns_scoped_bounded_cards(self):
        database, api = FakeDatabase(), FakeAPI()
        result = retrieval.handle({"task_id": 42, "question": "权限检查怎么验证？"}, database, api)
        self.assertTrue(result["completed"])
        self.assertEqual(result["conversation_id"], 7)
        self.assertEqual(FakeRuntime.checked_tasks, [42])
        self.assertEqual(FakeRuntime.gets, [{"id": REAL_ID, "task_id": 42}])
        self.assertEqual(result["experiences"][0]["status"], "candidate")
        cards = json.dumps(result["experiences"])
        for forbidden in ("PRIVATE RAW", "source_task_id", "source_key", "snapshot_id", "evidence_ids", "activity:123"):
            self.assertNotIn(forbidden, cards)
        self.assertFalse(any(path.endswith("/stop") for path, _ in api.requests))

    def test_real_search_with_no_hits_can_return_an_honest_empty_answer(self):
        database = FakeDatabase(transcript(hits=False))
        result = retrieval.handle({"task_id": 42, "question": "没有经验时怎么办"}, database, FakeAPI())
        self.assertTrue(result["completed"])
        self.assertEqual(result["experiences"], [])
        self.assertIn("没有检索到", result["answer"])
        self.assertFalse(FakeRuntime.gets)

    def test_refined_search_can_cite_a_genuine_second_result_group(self):
        ids = [character * 24 for character in "acde"]
        original = copy.deepcopy(FakeRuntime.cards[REAL_ID])
        for entry_id in ids:
            FakeRuntime.cards[entry_id] = dict(original, id=entry_id)
        rows = [
            row("tool_use", "experience_search", {"task_id": 42, "query": "first mechanism"}),
            row("tool_result", "experience_search", {"experiences": [{"id": value} for value in ids[:3]]}),
            row("tool_use", "experience_search", {"task_id": 42, "query": "refined mechanism"}),
            row("tool_result", "experience_search", {"experiences": [{"id": ids[3]}]}),
            row("result", detail="第二次检索的相关候选 " + ids[3] + " 需要当前证据验证。"),
        ]
        result = retrieval.collect_answer(FakeDatabase(rows), 7, 42, 3)
        self.assertEqual(result["experiences"][0]["id"], ids[3])
        self.assertIn(ids[3], result["answer"])
        self.assertLessEqual(len(result["experiences"]), 3)
        self.assertTrue(all(call["task_id"] == 42 for call in FakeRuntime.gets))

    def test_over_limit_genuine_citations_are_bounded_without_a_false_error(self):
        ids = [character * 24 for character in "acde"]
        original = copy.deepcopy(FakeRuntime.cards[REAL_ID])
        for entry_id in ids:
            FakeRuntime.cards[entry_id] = dict(original, id=entry_id)
        rows = [
            row("tool_use", "experience_search", {"task_id": 42, "query": "first mechanism"}),
            row("tool_result", "experience_search", {"experiences": [{"id": value} for value in ids[:3]]}),
            row("tool_use", "experience_search", {"task_id": 42, "query": "refined mechanism"}),
            row("tool_result", "experience_search", {"experiences": [{"id": ids[3]}]}),
            row("result", detail="真实候选：" + "、".join(ids)),
        ]
        result = retrieval.collect_answer(FakeDatabase(rows), 7, 42, 3)
        self.assertEqual([card["id"] for card in result["experiences"]], ids[:3])
        self.assertNotIn(ids[3], result["answer"])
        self.assertEqual({call["id"] for call in FakeRuntime.gets}, set(ids))

    def test_no_search_is_rejected_and_helper_is_stopped(self):
        api = FakeAPI()
        with self.assertRaises(retrieval.RetrievalError):
            retrieval.handle({"task_id": 42, "question": "机制"}, FakeDatabase([row("result", detail="想当然回答")]), api)
        self.assertTrue(any(path == "/api/conversations/7/stop" for path, _ in api.requests))

    def test_search_call_without_successful_result_is_not_a_real_search(self):
        rows = [row("tool_use", "experience_search", {"task_id": 42, "query": "authorization"}),
                row("result", detail="没有相关经验。")]
        with self.assertRaises(retrieval.RetrievalError):
            retrieval.collect_answer(FakeDatabase(rows), 7, 42, 3)

    def test_wrong_scope_unexpected_tool_and_fabricated_ids_are_rejected(self):
        wrong_scope = transcript(task_id=99)
        unexpected_tool = transcript()[:-1] + [row("tool_use", "Bash", {"command": "anything"}), row("result", detail="完成")]
        fabricated = transcript(answer="引用不存在的经验 " + UNKNOWN_ID)
        for rows in (wrong_scope, unexpected_tool, fabricated):
            with self.subTest(rows=rows), self.assertRaises(retrieval.RetrievalError):
                retrieval.collect_answer(FakeDatabase(rows), 7, 42, 3)

    def test_error_object_or_invalid_json_is_never_reported_as_no_hits(self):
        errors = [row("tool_result", "experience_search", {"error": "library unavailable"}),
                  row("tool_result", "experience_search", "{broken-json"),
                  row("tool_result", "experience_search", {"notice": "missing records"}),
                  row("tool_result", "experience_search", {"experiences": "not-an-array"})]
        for error in errors:
            rows = transcript(task_id=0, hits=False)
            rows[1] = error
            with self.subTest(error=error), self.assertRaises(retrieval.RetrievalError):
                retrieval.collect_answer(FakeDatabase(rows), 7, 0, 3)

    def test_invalid_json_search_arguments_cannot_silently_become_scope_zero(self):
        rows = transcript(task_id=0, hits=False)
        rows[0] = row("tool_use", "experience_search", "not-json")
        with self.assertRaises(retrieval.RetrievalError):
            retrieval.collect_answer(FakeDatabase(rows), 7, 0, 3)

    def test_timeout_stops_only_the_created_helper_conversation(self):
        clock, api = FakeClock(), FakeAPI([{"running": True, "items": []}])
        result = retrieval.handle({"task_id": 42, "question": "机制"}, FakeDatabase(), api,
                                  wait_seconds=2, clock=clock, pause=clock.pause)
        self.assertFalse(result["completed"])
        self.assertEqual(api.requests[-1], ("/api/conversations/7/stop", {}))

    def test_disabled_helper_and_invalid_inputs_do_not_start_a_conversation(self):
        api = FakeAPI()
        with self.assertRaises(retrieval.RetrievalError):
            retrieval.handle({"task_id": 42, "question": "机制"}, FakeDatabase(enabled=False), api)
        self.assertEqual(api.requests, [])
        for payload in (None, [], {"task_id": True, "question": "x"}, {"task_id": -1, "question": "x"},
                        {"task_id": 0, "question": " "}, {"task_id": 0, "question": "x", "tags": [3]},
                        {"task_id": 0, "question": "x", "limit": 4}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                retrieval.validate_request(payload)


class Response:
    def __init__(self, url, data=b'{"id":7}'):
        self.url, self.data = url, data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, size):
        return self.data[:size]


class NativeAPITests(unittest.TestCase):
    def setUp(self):
        self.api = retrieval.NativeAPI("/not/read/in/tests")
        self.token_patch = patch.object(self.api, "token", return_value="synthetic-token")
        self.token_patch.start()
        self.addCleanup(self.token_patch.stop)

    def test_only_fixed_loopback_conversation_routes_are_requested(self):
        paths = ("/api/conversations", "/api/conversations/7", "/api/conversations/7/messages",
                 "/api/conversations/7/messages?since=0", "/api/conversations/7/stop")
        for path in paths:
            with patch.object(self.api.opener, "open", return_value=Response(retrieval.BASE_URL + path)) as opened:
                self.assertEqual(self.api.request(path), {"id": 7})
                request = opened.call_args.args[0]
                self.assertEqual(request.full_url, "http://127.0.0.1:8787" + path)
                self.assertEqual(opened.call_args.kwargs["timeout"], 12)
        with patch.object(self.api.opener, "open") as opened:
            for path in ("https://evil.test/api/conversations", "//evil.test", "/api/tasks", "/api/conversations/0",
                         "/api/conversations/7/../../tasks", "/api/conversations/7/messages?url=https://evil.test"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.api.request(path)
            opened.assert_not_called()

    def test_redirect_and_malformed_native_response_are_rejected(self):
        self.assertIsNone(retrieval.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.test"))
        for response in (Response("https://evil.test"), Response(retrieval.BASE_URL + "/api/conversations", b"not-json"),
                         Response(retrieval.BASE_URL + "/api/conversations", b"[]"),
                         Response(retrieval.BASE_URL + "/api/conversations", b"x" * (1024 * 1024 + 1))):
            with patch.object(self.api.opener, "open", return_value=response), self.assertRaises(retrieval.RetrievalError):
                self.api.request("/api/conversations")


if __name__ == "__main__":
    unittest.main(verbosity=2)
