#!/usr/bin/env python3
"""/client-range-decision 调用示例（仅依赖 Python 3 标准库）。

演示把客户端的 Range / If-Range 请求头交给服务做决策：
  1. If-Range 与当前强 ETag 匹配 + 多段 Range（含一个不可满足段）：
     得到 206 决策，其中 plan 与 /plan 的返回完全一致——据此模拟逐块回源，
     再调用 /assemble 重组出决策中每个交付范围的字节；
  2. If-Range 不匹配（对象已更新）：得到忽略 Range 的 200 完整对象决策；
  3. 所有段均不可满足：得到 416 决策（Content-Range: bytes */<total>）。

用法：
    python examples/client_range_decision_example.py

环境变量：
    RANGE_PLANNER_URL  服务地址（默认 http://127.0.0.1:8080）
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("RANGE_PLANNER_URL", "http://127.0.0.1:8080")

OBJECT_LENGTH = 256
CURRENT_ETAG = '"v3-strong"'
OLD_ETAG = '"v1-stale"'


def call(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code} on {path}: {exc.read().decode()}")
        sys.exit(1)


def decide(range_header: str, if_range: str | None = None) -> dict:
    return call("/client-range-decision", {
        "object_length": OBJECT_LENGTH,
        "etag": CURRENT_ETAG,
        "range": range_header,
        **({"if_range": if_range} if if_range is not None else {}),
        "max_gap": 8,
        "fetch_limit": 128,
    })


def main() -> None:
    obj = bytes((i % 256 for i in range(OBJECT_LENGTH)))

    # 1. If-Range 匹配 + 多段 Range：suffix、闭区间、被跳过的反转段。
    print("== 1) If-Range 匹配，多段 Range（含不可满足段 500-100） ==")
    decision = decide("bytes=-16,0-99,500-100", CURRENT_ETAG)
    print(f"决策：{decision['decision']}（HTTP {decision['status_code']}）")
    for rng in decision["ranges"]:
        print(
            f"  交付范围 index={rng['index']} "
            f"segment={rng['segment_index']} {rng['type']} "
            f"[{rng['start']},{rng['end']}] ({rng['length']} 字节)"
        )
    for skip in decision["skipped_ranges"]:
        print(f"  跳过段 segment={skip['segment_index']}：{skip['reason']}")

    # plan 与 /plan 的返回同构：按 blocks 回源（这里用对象字节模拟上游 206），
    # 再连同 mappings 提交给 /assemble。
    plan = decision["plan"]
    contents = []
    for blk in plan["blocks"]:
        s, e = blk["start"], blk["end"]
        contents.append({
            "block_index": blk["index"],
            "data_b64": base64.b64encode(obj[s: e + 1]).decode("ascii"),
        })
        print(f"  模拟回源 {blk['range_header']} -> {e - s + 1} 字节")

    assembled = call("/assemble", {
        "object_length": OBJECT_LENGTH,
        "blocks": plan["blocks"],
        "mappings": plan["mappings"],
        "contents": contents,
    })
    for got, want in zip(assembled["ranges"], decision["ranges"]):
        data = base64.b64decode(got["data_b64"])
        assert data == obj[want["start"]: want["end"] + 1]
        print(
            f"  /assemble 范围 {got['index']}: {got['length']} 字节，"
            f"与决策 [{want['start']},{want['end']}] 逐字节一致"
        )

    # 2. If-Range 不匹配：忽略 Range，代理应返回完整对象。
    print("\n== 2) If-Range 携带过期 ETag ==")
    decision = decide("bytes=0-99", OLD_ETAG)
    print(
        f"决策：{decision['decision']}（HTTP {decision['status_code']}）"
        f" reason={decision['reason']}"
    )
    ev = decision["if_range"]
    print(
        f"  If-Range {ev['value']} weak={ev['weak']} "
        f"matched={ev['matched']} -> 应回源完整对象（200）"
    )

    # 3. 全部不可满足：416 + Content-Range: bytes */<total>。
    print("\n== 3) Range 全部不可满足 ==")
    decision = decide("bytes=1000-2000,9999-0")
    print(
        f"决策：{decision['decision']}（HTTP {decision['status_code']}）"
    )
    print(f"  响应头：{decision['headers']}")
    print(f"  不可满足段：{[s['reason'] for s in decision['skipped_ranges']]}")

    print("\n全部场景执行完成。")


if __name__ == "__main__":
    main()
