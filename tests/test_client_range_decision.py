# -*- coding: utf-8 -*-
"""POST /client-range-decision 的行为测试。

覆盖：
- 206 决策：单段闭区间、多段（按对象偏移排序交付，segment_index 回溯原始
  段）、开放终点 bytes=N-、超尾 last-byte-pos 钳制、suffix bytes=-N（超过
  对象长度时回落为整个对象）、max_gap 合并、cached_blocks 透传；返回的
  plan 可直接驱动 /assemble 重组出与决策 ranges 一致的字节；
- 跳段：反转区间、first-byte-pos 越过末尾、bytes=-0 被跳过，其余段仍交付；
- 416 决策：全部不可满足（含空对象 suffix / bytes=0-），响应头携带
  Content-Range: bytes */<total>；
- 200 决策：无 Range（no_range）；If-Range 与当前强 ETag / Last-Modified
  不匹配时即使 Range 不可满足也忽略 Range（if_range_mismatch）；弱 ETag
  永不强匹配；entity-tag 与 HTTP-date 跨类型不匹配；
- If-Range 匹配：强 ETag 全等、HTTP-date 三种形式（IMF-fixdate / RFC 850 /
  asctime）按同一时刻匹配；
- 422：Range 头语法非法（错误单位、缺 =、空段、段内空白、非数字、多个
  '-'、前导 +、CR/LF 注入、非 ASCII 等）loc=range；当前 ETag 为弱标签或
  非法 loc=etag；当前 Last-Modified / If-Range 日期非法（错误星期、不存在
  的日期、非 GMT、附加文本）loc=last_modified / if_range；If-Range 形态
  非法 loc=if_range；etag 与 last_modified 均缺省、规划参数缺失等字段
  错误为 invalid_request；
- 优先级：If-Range 不匹配优先于 416；头值语法错误优先于 If-Range 不匹配；
  /plan 语义错误（无缓存时范围超过 fetch_limit）返回 unsatisfiable 422，
  range_index 为交付范围下标。

直接运行：python -m unittest discover -s tests
"""

from __future__ import annotations

import base64
import unittest

from app.main import app

try:
    from starlette.testclient import TestClient
except ImportError:  # pragma: no cover
    TestClient = None  # type: ignore[assignment]

OBJECT_LENGTH = 256
ETAG_V1 = '"v1-strong"'
ETAG_V2 = '"v2-other"'
LM = "Sun, 06 Nov 1994 08:49:37 GMT"


@unittest.skipIf(TestClient is None, "需要安装 starlette（随 fastapi 安装）")
class ClientRangeDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self.obj = bytes((i % 256 for i in range(OBJECT_LENGTH)))

    # ----------------------------- 构造工具 -----------------------------

    def post(self, body: dict):
        return self.client.post("/client-range-decision", json=body)

    def base(self, **overrides) -> dict:
        body = {
            "object_length": OBJECT_LENGTH,
            "etag": ETAG_V1,
            "max_gap": 0,
            "fetch_limit": 1024,
        }
        body.update(overrides)
        return body

    def err(self, resp, code: str, loc: str | None = None) -> dict:
        self.assertEqual(resp.status_code, 422, resp.text)
        payload = resp.json()
        self.assertEqual(payload["error"], code, payload)
        detail = payload["detail"][0]
        self.assertIn("message", detail)
        if loc is not None:
            self.assertEqual(detail.get("loc"), loc, detail)
        return detail

    # ----------------------------- 206：基础 -----------------------------

    def test_single_interval_206(self):
        resp = self.post(self.base(range="bytes=10-19"))
        self.assertEqual(resp.status_code, 200, resp.text)
        d = resp.json()
        self.assertEqual(d["decision"], "partial_content")
        self.assertEqual(d["status_code"], 206)
        self.assertEqual(d["headers"], {"Accept-Ranges": "bytes"})
        self.assertEqual(d["object_length"], OBJECT_LENGTH)
        self.assertIsNone(d["if_range"])
        (rng,) = d["ranges"]
        self.assertEqual(
            rng,
            {
                "index": 0,
                "segment_index": 0,
                "type": "interval",
                "start": 10,
                "end": 19,
                "length": 10,
            },
        )
        self.assertEqual(d["skipped_ranges"], [])
        (block,) = d["plan"]["blocks"]
        self.assertEqual(
            (block["start"], block["end"], block["length"], block["range_header"]),
            (10, 19, 10, "bytes=10-19"),
        )
        (mapping,) = d["plan"]["mappings"]
        self.assertEqual((mapping["index"], mapping["start"], mapping["end"]),
                         (0, 10, 19))

    def test_multiple_ranges_sorted_and_gap_merge(self):
        # 段顺序：末尾 suffix、靠前闭区间、靠后开放终点；交付按对象偏移排序。
        resp = self.post(self.base(
            range="bytes=-16,0-9,200-", max_gap=1000, fetch_limit=1024
        ))
        self.assertEqual(resp.status_code, 200, resp.text)
        d = resp.json()
        self.assertEqual(
            [(r["segment_index"], r["type"], r["start"], r["end"])
             for r in d["ranges"]],
            [(1, "interval", 0, 9), (2, "interval", 200, 255),
             (0, "suffix", 240, 255)],
        )
        # max_gap=1000 且 fetch_limit 足够：三个交付范围合并为一个回源块。
        self.assertEqual(
            [(b["start"], b["end"]) for b in d["plan"]["blocks"]],
            [(0, 255)],
        )
        self.assertEqual(
            [m["index"] for m in d["plan"]["mappings"]], [0, 1, 2]
        )

    def test_open_ended_and_clamping(self):
        # 开放终点钳到对象末尾；last-byte-pos 超尾同样钳制；suffix 超大回落。
        resp = self.post(self.base(range="bytes=250-,250-999,-9999"))
        self.assertEqual(resp.status_code, 200, resp.text)
        d = resp.json()
        self.assertEqual(
            [(r["segment_index"], r["start"], r["end"], r["length"])
             for r in d["ranges"]],
            [(2, 0, 255, 256), (0, 250, 255, 6), (1, 250, 255, 6)],
        )
        # suffix 超大时 /plan 侧也规范化为整个对象。
        suffix_mapping = d["plan"]["mappings"][0]
        self.assertEqual(suffix_mapping["type"], "suffix")
        self.assertEqual((suffix_mapping["start"], suffix_mapping["end"]),
                         (0, 255))

    def test_suffix_normal_n(self):
        resp = self.post(self.base(range="bytes=-16"))
        d = resp.json()
        (rng,) = d["ranges"]
        self.assertEqual((rng["type"], rng["start"], rng["end"], rng["length"]),
                         ("suffix", 240, 255, 16))

    def test_ows_around_commas_accepted(self):
        # RFC 1#element：逗号两侧允许 OWS；整体首尾 OWS 也允许。
        resp = self.post(self.base(range="  bytes=0-9 , 20-29 "))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(
            [(r["start"], r["end"]) for r in resp.json()["ranges"]],
            [(0, 9), (20, 29)],
        )

    # --------------------------- 206：跳段语义 ---------------------------

    def test_skip_inverted_and_past_end(self):
        resp = self.post(
            self.base(range="bytes=0-9,100-50,300-400,256-")
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        d = resp.json()
        self.assertEqual(
            [(r["segment_index"], r["start"], r["end"]) for r in d["ranges"]],
            [(0, 0, 9)],
        )
        skipped = d["skipped_ranges"]
        self.assertEqual(
            [(s["segment_index"], s["reason"], s["kind"], s["start"], s["end"])
             for s in skipped],
            [
                (1, "inverted", "interval", 100, 50),
                (2, "start_past_end", "interval", 300, 400),
                (3, "start_past_end", "interval", 256, None),
            ],
        )

    def test_skip_suffix_zero(self):
        # bytes=-0 语法合法但永远不可满足，与另一个好段共存时只跳过 -0。
        resp = self.post(self.base(range="bytes=-0,10-19"))
        d = resp.json()
        self.assertEqual(
            [(r["segment_index"], r["start"]) for r in d["ranges"]], [(1, 10)]
        )
        (bad,) = d["skipped_ranges"]
        self.assertEqual(
            (bad["segment_index"], bad["kind"], bad["last_n"], bad["reason"]),
            (0, "suffix", 0, "start_past_end"),
        )

    # ----------------------------- 416 决策 -----------------------------

    def test_all_unsatisfiable_416(self):
        resp = self.post(self.base(range="bytes=300-400,500-100"))
        self.assertEqual(resp.status_code, 200, resp.text)
        d = resp.json()
        self.assertEqual(d["decision"], "range_not_satisfiable")
        self.assertEqual(d["status_code"], 416)
        self.assertEqual(
            d["headers"],
            {
                "Accept-Ranges": "bytes",
                "Content-Range": f"bytes */{OBJECT_LENGTH}",
            },
        )
        self.assertNotIn("ranges", d)
        self.assertNotIn("plan", d)
        self.assertEqual([s["segment_index"] for s in d["skipped_ranges"]], [0, 1])
        self.assertEqual(
            [s["reason"] for s in d["skipped_ranges"]],
            ["start_past_end", "inverted"],
        )

    def test_416_empty_object(self):
        for header, kind in (("bytes=-10", "suffix"), ("bytes=0-", "interval")):
            with self.subTest(header=header):
                resp = self.post(self.base(
                    object_length=0, etag='"v0"', range=header
                ))
                d = resp.json()
                self.assertEqual(d["decision"], "range_not_satisfiable")
                self.assertEqual(d["headers"]["Content-Range"], "bytes */0")
                (bad,) = d["skipped_ranges"]
                self.assertEqual(bad["kind"], kind)
                self.assertEqual(
                    bad["reason"],
                    "empty_object" if kind == "suffix" else "start_past_end",
                )

    def test_416_suffix_zero_on_nonempty(self):
        resp = self.post(self.base(range="bytes=-0"))
        d = resp.json()
        self.assertEqual(d["decision"], "range_not_satisfiable")
        self.assertEqual(d["headers"]["Content-Range"], f"bytes */{OBJECT_LENGTH}")

    # ----------------------------- 200 决策 -----------------------------

    def test_no_range_is_full_object(self):
        resp = self.post(self.base())
        d = resp.json()
        self.assertEqual(d["decision"], "full_object")
        self.assertEqual(d["status_code"], 200)
        self.assertEqual(d["reason"], "no_range")
        self.assertEqual(d["headers"], {"Accept-Ranges": "bytes"})
        self.assertIsNone(d["if_range"])

    def test_no_range_with_matching_if_range(self):
        resp = self.post(self.base(if_range=ETAG_V1))
        d = resp.json()
        self.assertEqual(d["decision"], "full_object")
        self.assertEqual(d["reason"], "no_range")
        self.assertTrue(d["if_range"]["matched"])

    def test_if_range_etag_mismatch_ignores_range(self):
        # 即使 Range 本身不可满足（理应 416），If-Range 不匹配也优先 → 200。
        resp = self.post(self.base(range="bytes=900-1000", if_range=ETAG_V2))
        d = resp.json()
        self.assertEqual(d["decision"], "full_object")
        self.assertEqual(d["status_code"], 200)
        self.assertEqual(d["reason"], "if_range_mismatch")
        ev = d["if_range"]
        self.assertEqual(
            (ev["kind"], ev["weak"], ev["value"], ev["compared_with"], ev["matched"]),
            ("etag", False, ETAG_V2, "etag", False),
        )

    def test_if_range_weak_etag_never_matches(self):
        resp = self.post(
            self.base(range="bytes=0-9", if_range='W/' + ETAG_V1)
        )
        d = resp.json()
        self.assertEqual(d["decision"], "full_object")
        self.assertEqual(d["reason"], "if_range_mismatch")
        ev = d["if_range"]
        self.assertEqual((ev["kind"], ev["weak"], ev["matched"]),
                         ("etag", True, False))

    def test_if_range_lowercase_w_prefix_also_weak(self):
        resp = self.post(
            self.base(range="bytes=0-9", if_range='w/' + ETAG_V1)
        )
        d = resp.json()
        self.assertEqual(d["reason"], "if_range_mismatch")
        self.assertTrue(d["if_range"]["weak"])
        self.assertFalse(d["if_range"]["matched"])

    def test_if_range_strong_etag_match_delivers_206(self):
        resp = self.post(self.base(range="bytes=0-9", if_range=ETAG_V1))
        d = resp.json()
        self.assertEqual(d["decision"], "partial_content")
        ev = d["if_range"]
        self.assertEqual(
            (ev["kind"], ev["weak"], ev["compared_with"], ev["matched"]),
            ("etag", False, "etag", True),
        )

    def test_if_range_date_match_and_mismatch(self):
        resp = self.post(self.base(
            etag=None, last_modified=LM, range="bytes=0-9", if_range=LM
        ))
        d = resp.json()
        self.assertEqual(d["decision"], "partial_content")
        self.assertEqual(
            (d["if_range"]["kind"], d["if_range"]["compared_with"],
             d["if_range"]["matched"]),
            ("date", "last_modified", True),
        )
        resp = self.post(self.base(
            etag=None, last_modified=LM, range="bytes=0-9",
            if_range="Wed, 09 Nov 1994 08:49:37 GMT",
        ))
        d = resp.json()
        self.assertEqual(d["decision"], "full_object")
        self.assertEqual(d["reason"], "if_range_mismatch")
        self.assertFalse(d["if_range"]["matched"])

    def test_if_range_date_legacy_forms(self):
        # RFC 850 形式与 asctime 形式表示同一时刻时也应匹配。
        resp = self.post(self.base(
            etag=None, last_modified=LM, range="bytes=0-9",
            if_range="Sunday, 06-Nov-94 08:49:37 GMT",
        ))
        self.assertEqual(resp.json()["decision"], "partial_content")
        resp = self.post(self.base(
            etag=None, last_modified=LM, range="bytes=0-9",
            if_range="Sun Nov  6 08:49:37 1994",
        ))
        self.assertEqual(resp.json()["decision"], "partial_content")

    def test_if_range_rfc850_two_digit_year_pivot(self):
        # RFC 9110 启发式：67 → 2067，68 → 1968，两端各验证一次。
        resp = self.post(self.base(
            etag=None,
            last_modified="Sunday, 06-Nov-67 08:49:37 GMT",
            range="bytes=0-9",
            if_range="Sun, 06 Nov 2067 08:49:37 GMT",
        ))
        self.assertTrue(resp.json()["if_range"]["matched"])
        resp = self.post(self.base(
            etag=None,
            last_modified="Wednesday, 06-Nov-68 08:49:37 GMT",
            range="bytes=0-9",
            if_range="Wed, 06 Nov 1968 08:49:37 GMT",
        ))
        self.assertTrue(resp.json()["if_range"]["matched"])

    def test_if_range_cross_type_mismatch(self):
        # If-Range 给 entity-tag，但当前只有 Last-Modified：类型不匹配 → 200。
        resp = self.post(self.base(
            etag=None, last_modified=LM, range="bytes=0-9", if_range=ETAG_V1
        ))
        d = resp.json()
        self.assertEqual(d["decision"], "full_object")
        self.assertEqual(d["if_range"]["compared_with"], "etag")
        self.assertFalse(d["if_range"]["matched"])
        # 反之：If-Range 给日期，当前只有 ETag —— 日期解析必须成功，但无法匹配。
        resp = self.post(self.base(
            range="bytes=0-9", if_range=LM
        ))
        d = resp.json()
        self.assertEqual(d["decision"], "full_object")
        self.assertEqual(d["if_range"]["kind"], "date")
        self.assertEqual(d["if_range"]["compared_with"], "last_modified")
        self.assertFalse(d["if_range"]["matched"])

    # ----------------------------- 422：Range -----------------------------

    def test_malformed_range_values(self):
        bad = [
            "bytes=",            # 没有任何段
            "bytes=0-9,,10-20",  # 空段
            "0-9",               # 缺单位与 =
            "bytes 0-9",         # 缺 =
            "items=0-9",         # 不支持的单位
            "bytes=0",           # 缺 -
            "bytes=-",           # 既无首偏移也无 suffix 长度
            "bytes=--",          # 多个 -
            "bytes=1-2-3",       # 多个 -
            "bytes=-1-2",        # suffix 段多余 -
            "bytes=a-b",         # 非数字
            "bytes=0x-9",        # 十六进制
            "bytes=+0-9",        # 前导 +
            "bytes=0 -9",        # 段内空白
            "bytes=0-\t9",       # 段内 tab
            "bytes=-abc",        # suffix 非数字
            "bytes=abc-",        # 开放终点首偏移非数字
            "bytes=9-x",         # last 非数字且非开放终点
        ]
        for header in bad:
            with self.subTest(header=header):
                resp = self.post(self.base(range=header))
                self.err(resp, "invalid_header", "range")

    def test_range_control_chars_and_non_ascii(self):
        resp = self.post(self.base(range="bytes=0-9\r\nX-Inject: 1"))
        self.err(resp, "invalid_header", "range")
        resp = self.post(self.base(range="bytes=0-9\n"))
        self.err(resp, "invalid_header", "range")
        resp = self.post(self.base(range="bytes=Ø-9"))
        self.err(resp, "invalid_header", "range")

    def test_malformed_range_reported_even_if_range_mismatches(self):
        # 语法错误是请求契约错误，优先于 If-Range 不匹配分支返回 422。
        resp = self.post(
            self.base(range="bytes=GARBAGE", if_range=ETAG_V2)
        )
        self.err(resp, "invalid_header", "range")

    # -------------------------- 422：当前验证器 --------------------------

    def test_current_weak_etag_rejected(self):
        resp = self.post(self.base(etag='W/"v1"', range="bytes=0-9"))
        self.err(resp, "weak_etag", "etag")
        resp = self.post(self.base(etag='w/"v1"', range="bytes=0-9"))
        self.err(resp, "weak_etag", "etag")

    def test_current_etag_malformed(self):
        for value in ["v1", '"v1', 'v1"', '"v 1"', '""', '"a\nb"']:
            with self.subTest(value=value):
                resp = self.post(self.base(etag=value))
                self.err(resp, "invalid_etag", "etag")

    def test_current_last_modified_malformed(self):
        bad = [
            "Sunx, 06 Nov 1994 08:49:37 GMT",  # 错误星期缩写
            "Mon, 06 Nov 1994 08:49:37 GMT",   # 星期与日期不一致
            "Wed, 30 Feb 1994 08:49:37 GMT",   # 不存在的日期
            "Sun, 06 Nov 1994 24:49:37 GMT",   # 越界钟点
            "Sun, 06 Nov 1994 08:49:37 UTC",   # 非 GMT
            "06 Nov 1994 08:49:37 GMT",        # 缺星期
            "not-a-date",
        ]
        for value in bad:
            with self.subTest(value=value):
                resp = self.post(self.base(
                    etag=None, last_modified=value
                ))
                self.err(resp, "invalid_http_date", "last_modified")

    # --------------------------- 422：If-Range ---------------------------

    def test_if_range_malformed(self):
        resp = self.post(self.base(range="bytes=0-9", if_range="W/"))
        self.err(resp, "invalid_if_range_etag", "if_range")
        resp = self.post(self.base(range="bytes=0-9", if_range="v1"))
        self.err(resp, "invalid_http_date", "if_range")
        resp = self.post(
            self.base(etag=None, last_modified=LM, range="bytes=0-9",
                      if_range="Sun, 06 Nov 1994 08:49:37")
        )
        self.err(resp, "invalid_http_date", "if_range")

    def test_if_range_malformed_without_range_still_422(self):
        resp = self.post(self.base(if_range="garbage"))
        self.err(resp, "invalid_http_date", "if_range")

    # --------------------------- 422：字段校验 ---------------------------

    def test_missing_both_validators(self):
        body = self.base()
        body.pop("etag")
        resp = self.post(body)
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.json()["error"], "invalid_request")

    def test_missing_planning_params(self):
        for key in ("max_gap", "fetch_limit"):
            with self.subTest(key=key):
                body = self.base(range="bytes=0-9")
                body.pop(key)
                resp = self.post(body)
                self.assertEqual(resp.status_code, 422)
                self.assertEqual(resp.json()["error"], "invalid_request")

    def test_fetch_limit_must_be_positive(self):
        resp = self.post(self.base(range="bytes=0-9", fetch_limit=0))
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.json()["error"], "invalid_request")

    def test_duplicate_cache_ids_rejected(self):
        resp = self.post(self.base(
            range="bytes=0-99",
            cached_blocks=[
                {"cache_id": "a", "start": 0, "end": 9},
                {"cache_id": "a", "start": 20, "end": 29},
            ],
        ))
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.json()["error"], "invalid_request")

    def test_plan_semantics_error_surfaces_422(self):
        # 无 cached_blocks 时单段超过 fetch_limit：沿用 /plan 的 422 契约，
        # range_index 是交付范围下标（跳过段不占位，按下标即对象偏移排序）。
        resp = self.post(self.base(
            range="bytes=0-99,500-100", max_gap=0, fetch_limit=64
        ))
        self.assertEqual(resp.status_code, 422, resp.text)
        payload = resp.json()
        self.assertEqual(payload["error"], "unsatisfiable")
        self.assertEqual(payload["range_index"], 0)

    # --------------------- cached_blocks 透传 /assemble ---------------------

    def test_cached_blocks_flow_into_plan(self):
        resp = self.post(self.base(
            range="bytes=0-99",
            cached_blocks=[{"cache_id": "cdn-a", "start": 40, "end": 59}],
        ))
        d = resp.json()
        self.assertEqual(d["decision"], "partial_content")
        self.assertEqual(
            [(b["start"], b["end"]) for b in d["plan"]["blocks"]],
            [(0, 39), (60, 99)],
        )
        self.assertEqual(
            [s["source"] for s in d["plan"]["mappings"][0]["slices"]],
            ["fetch", "cache", "fetch"],
        )
        self.assertEqual(
            [cb["cache_id"] for cb in d["plan"]["cached_blocks"]], ["cdn-a"]
        )

    def _assemble_via_decision(self, range_header: str, **overrides):
        """/client-range-decision → 模拟回源 → /assemble，返回 (决策, 重组结果)。"""
        resp = self.post(self.base(range=range_header, **overrides))
        self.assertEqual(resp.status_code, 200, resp.text)
        d = resp.json()
        self.assertEqual(d["decision"], "partial_content")
        plan = d["plan"]
        contents = [
            {
                "block_index": b["index"],
                "data_b64": base64.b64encode(
                    self.obj[b["start"]: b["end"] + 1]
                ).decode("ascii"),
            }
            for b in plan["blocks"]
        ]
        assembled = self.client.post("/assemble", json={
            "object_length": OBJECT_LENGTH,
            "blocks": plan["blocks"],
            "mappings": plan["mappings"],
            "contents": contents,
            "cached_blocks": plan.get("cached_blocks", []),
            "cache_contents": [
                {
                    "cache_id": cb["cache_id"],
                    "data_b64": base64.b64encode(
                        self.obj[cb["start"]: cb["end"] + 1]
                    ).decode("ascii"),
                }
                for cb in plan.get("cached_blocks", [])
            ],
        })
        self.assertEqual(assembled.status_code, 200, assembled.text)
        return d, assembled.json()

    def test_plan_is_assemble_ready_single(self):
        d, out = self._assemble_via_decision("bytes=100-199")
        self.assertEqual(
            base64.b64decode(out["ranges"][0]["data_b64"]), self.obj[100:200]
        )
        self.assertEqual(len(out["ranges"]), len(d["ranges"]))

    def test_plan_is_assemble_ready_multi_with_skips_and_cache(self):
        d, out = self._assemble_via_decision(
            "bytes=-16,0-99,900-100,200-219",
            max_gap=8,
            fetch_limit=64,
            cached_blocks=[{"cache_id": "cdn-a", "start": 40, "end": 59}],
        )
        # 交付范围：[0,99]、[200,219]、[240,255]（段 2 反转被跳过）。
        self.assertEqual(
            [(r["start"], r["end"], r["type"]) for r in d["ranges"]],
            [(0, 99, "interval"), (200, 219, "interval"),
             (240, 255, "suffix")],
        )
        by_index = {r["index"]: r for r in out["ranges"]}
        for dr in d["ranges"]:
            got = base64.b64decode(by_index[dr["index"]]["data_b64"])
            self.assertEqual(got, self.obj[dr["start"]: dr["end"] + 1])

    # ------------------------------ 其他细节 ------------------------------

    def test_decision_response_has_discriminator_and_no_extra_fields(self):
        resp = self.post(self.base(range="bytes=0-9"))
        d = resp.json()
        self.assertEqual(d["decision"], "partial_content")
        # 206 决策不应携带仅属于其他决策的字段。
        self.assertNotIn("reason", d)
        resp = self.post(self.base())
        d = resp.json()
        self.assertNotIn("plan", d)
        self.assertNotIn("ranges", d)
        self.assertNotIn("skipped_ranges", d)

    def test_openapi_schema_generated(self):
        resp = self.client.get("/openapi.json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("/client-range-decision", resp.json()["paths"])


if __name__ == "__main__":
    unittest.main()
