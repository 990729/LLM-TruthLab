"""Extended Anti-Contamination Dynamic IQ Question Bank (v11.2).

Provides 14 additional 100% seed-controlled, programmatically verified
challenges across all 10 cognitive & practical engineering dimensions so the
IQ battery has 31 distinct generator types and runs 2x more questions per audit.
"""

from __future__ import annotations

import heapq
import json
import random
import re
import sqlite3
from fractions import Fraction
from typing import Any

from .probes_iq import (
    _SAFE_BUILTINS,
    _ast_is_safe_pure_python,
    _extract_json_obj,
    _int_to_cn_financial,
)


def _extract_func_code(raw: str, func_name: str) -> str:
    s = re.sub(r"<think>.*?</think>", "", raw or "", flags=re.S | re.I).strip()
    blocks = re.findall(r"```(?:python|py)?\s*(.*?)```", s, flags=re.S | re.I)
    if blocks:
        for b in reversed(blocks):
            if f"def {func_name}" in b:
                return b.strip()
        return blocks[-1].strip()
    m = re.search(rf"(def\s+{re.escape(func_name)}\b.*)", s, flags=re.S)
    return m.group(1).strip() if m else s


# 1. Anti-Bias: Simpson's Paradox weighted reversal
def _build_anti_bias_simpson_paradox(rng: random.Random) -> dict[str, Any]:
    """Generate a guaranteed Simpson's Paradox dataset where A beats B in every subgroup but B beats A overall."""
    # Construct clean integer counts guaranteeing:
    # A mild: 19/20 (95%) > B mild: 90/100 (90%)
    # A severe: 50/100 (50%) > B severe: 8/20 (40%)
    # Overall A: 69/120 (57.5%) < Overall B: 98/120 (81.67%)!
    scale = rng.choice([1, 2, 3, 5])
    a_m_ok, a_m_tot = 19 * scale, 20 * scale
    b_m_ok, b_m_tot = 90 * scale, 100 * scale
    a_s_ok, a_s_tot = rng.choice([48, 50, 52]) * scale, 100 * scale
    b_s_ok, b_s_tot = rng.choice([7, 8, 9]) * scale, 20 * scale

    a_all_ok = a_m_ok + a_s_ok
    a_all_tot = a_m_tot + a_s_tot
    b_all_ok = b_m_ok + b_s_ok
    b_all_tot = b_m_tot + b_s_tot
    a_pct = round(a_all_ok / a_all_tot * 100.0, 2)
    b_pct = round(b_all_ok / b_all_tot * 100.0, 2)

    prompt = (
        "Two medical clinics report exact recovery counts across Mild and Severe patients:\n"
        f"- Clinic A: Mild = {a_m_ok}/{a_m_tot} recovered; Severe = {a_s_ok}/{a_s_tot} recovered.\n"
        f"- Clinic B: Mild = {b_m_ok}/{b_m_tot} recovered; Severe = {b_s_ok}/{b_s_tot} recovered.\n\n"
        "Carefully compute BOTH clinics' TRUE overall combined recovery percentages (rounded to 2 decimals) "
        "and identify which clinic has the higher OVERALL recovery rate vs higher rate in EACH subgroup.\n"
        'Return ONLY strict JSON: {"overall_winner": "A"|"B", "subgroup_winner": "A"|"B", '
        '"clinic_a_overall_pct": <number>, "clinic_b_overall_pct": <number>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        ow = str(obj.get("overall_winner", "")).strip().upper()
        sw = str(obj.get("subgroup_winner", "")).strip().upper()
        try:
            ga = float(obj.get("clinic_a_overall_pct", -1))
            gb = float(obj.get("clinic_b_overall_pct", -1))
        except Exception:
            ga, gb = -1.0, -1.0
        ok_w = (ow == "B" and sw == "A")
        ok_n = abs(ga - a_pct) <= 0.15 and abs(gb - b_pct) <= 0.15
        if ok_w and ok_n:
            return 1.0, f"辛普森悖论精准识破（总体 B={b_pct}% > A={a_pct}%，分组均为 A 胜）"
        if ok_w:
            return 0.65, f"悖论方向正确，但总体百分比计算有误（期 A={a_pct}%, B={b_pct}%）"
        return 0.0, f"落入直觉均值陷阱（答 overall={ow}, subgroup={sw}，期 B / A）"

    return {
        "id": "iq_anti_bias_simpson",
        "dimension": "anti_bias",
        "title": "辛普森悖论加权反转陷阱",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": {"overall_winner": "B", "subgroup_winner": "A", "a_pct": a_pct, "b_pct": b_pct},
        "grader": grade,
    }


# 2. Anti-Bias: Harmonic Mean Round-Trip Speed Trap
def _build_anti_bias_harmonic_speed(rng: random.Random) -> dict[str, Any]:
    v1 = rng.choice([20, 30, 40, 45, 60])
    v2 = rng.choice([60, 75, 80, 90, 120])
    while v1 == v2:
        v2 = rng.choice([60, 75, 90, 120])
    exact = Fraction(2 * v1 * v2, v1 + v2)
    ans_str = f"{exact.numerator}/{exact.denominator}" if exact.denominator != 1 else str(exact.numerator)
    ans_val = float(exact)

    prompt = (
        f"A drone flies from Base X to Base Y at a constant speed of {v1} km/h, "
        f"and immediately returns along the exact same route from Y to X at a constant speed of {v2} km/h.\n"
        "What is the drone's EXACT average speed for the entire round trip (in km/h)? "
        "(Do NOT take the naive arithmetic mean!)\n"
        'Return ONLY strict JSON: {"exact_fraction": "<p/q or integer>", "decimal": <number>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            got_f = Fraction(str(obj.get("exact_fraction", "")).strip())
            if got_f == exact:
                return 1.0, f"调和平均速度精确命中 {ans_str} km/h"
        except Exception:
            pass
        try:
            got_d = float(obj.get("decimal", -1))
            if abs(got_d - ans_val) <= 0.05:
                return 0.85, f"小数结果精确 ({got_d:.2f} ≈ {ans_val:.2f})"
        except Exception:
            pass
        return 0.0, f"误算为算术平均或数值错（期 {ans_str} ≈ {ans_val:.2f}）"

    return {
        "id": "iq_anti_bias_harmonic",
        "dimension": "anti_bias",
        "title": "往返均速调和平均反直觉题",
        "difficulty": "medium",
        "max_score": 10.0,
        "prompt": prompt,
        "expected": ans_str,
        "grader": grade,
    }


# 3. Deductive Logic: Unique 5-Variable Propositional SAT Puzzle
def _build_logic_propositional_sat(rng: random.Random) -> dict[str, Any]:
    """Generate a guaranteed UNIQUE-solution 5-variable Boolean constraint system."""
    vars5 = ["P", "Q", "R", "S", "T"]
    sol = {v: rng.choice([True, False]) for v in vars5}

    # Build rich human-readable clauses true under `sol`, adding until unique across all 32 states!
    def _eval_clause(kind: str, a: str, b: str, st: dict[str, bool]) -> bool:
        if kind == "imp":
            return (not st[a]) or st[b]
        if kind == "xor":
            return st[a] != st[b]
        if kind == "eq":
            return st[a] == st[b]
        if kind == "nand":
            return not (st[a] and st[b])
        if kind == "or":
            return st[a] or st[b]
        if kind == "imp_not":
            return (not st[a]) or (not st[b])
        return True

    def _describe_clause(kind: str, a: str, b: str) -> str:
        if kind == "imp":
            return f"If {a} is True, then {b} MUST be True."
        if kind == "xor":
            return f"Exactly one of {a} and {b} is True (not both, not neither)."
        if kind == "eq":
            return f"{a} and {b} have the EXACT SAME truth value."
        if kind == "nand":
            return f"{a} and {b} CANNOT both be True."
        if kind == "or":
            return f"At least one of {a} or {b} is True."
        return f"If {a} is True, then {b} MUST be False."

    all_states = [{vars5[j]: bool((mask >> j) & 1) for j in range(5)} for mask in range(32)]
    cand_clauses: list[tuple[str, str, str]] = []
    for i, a in enumerate(vars5):
        for j, b in enumerate(vars5):
            if i == j:
                continue
            for kind in ("imp", "xor", "eq", "nand", "or", "imp_not"):
                if kind in ("xor", "eq", "nand", "or") and i > j:
                    continue
                if _eval_clause(kind, a, b, sol):
                    cand_clauses.append((kind, a, b))
    rng.shuffle(cand_clauses)

    picked: list[tuple[str, str, str]] = []
    surviving = list(all_states)
    # Add 1 anchor unary fact to break global duality if needed, then pick informative binary clauses
    anchor_v = rng.choice(vars5)
    anchor_val = sol[anchor_v]
    surviving = [st for st in surviving if st[anchor_v] == anchor_val]
    rules = [f"Fact 1: {anchor_v} is {'True' if anchor_val else 'False'}."]

    for cl in cand_clauses:
        if len(surviving) == 1:
            break
        nxt = [st for st in surviving if _eval_clause(cl[0], cl[1], cl[2], st)]
        if 1 <= len(nxt) < len(surviving):
            picked.append(cl)
            surviving = nxt
            rules.append(f"Rule {len(rules) + 1}: {_describe_clause(cl[0], cl[1], cl[2])}")

    # Guarantee uniqueness (fallback anchor if >1 survive)
    while len(surviving) > 1:
        diff_v = next(v for v in vars5 if any(st[v] != sol[v] for st in surviving))
        surviving = [st for st in surviving if st[diff_v] == sol[diff_v]]
        rules.append(f"Rule {len(rules) + 1}: {diff_v} is {'True' if sol[diff_v] else 'False'}.")

    prompt = (
        "Five Boolean switches P, Q, R, S, T are each either True or False. "
        "All rules below hold simultaneously and uniquely determine every switch:\n"
        + "\n".join(f"- {r}" for r in rules)
        + '\n\nReturn ONLY strict JSON with booleans: {"P": true|false, "Q": ..., "R": ..., "S": ..., "T": ...}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        hits = sum(1 for v in vars5 if isinstance(obj.get(v), bool) and obj[v] == sol[v])
        if hits == 5:
            return 1.0, "5 变量命题逻辑约束满足求解 100% 精确"
        return round((hits / 5.0) * 0.5, 2) if hits >= 4 else 0.0, f"命题逻辑仅对 {hits}/5 个变量（期 {sol}）"

    return {
        "id": "iq_logic_sat5",
        "dimension": "deductive_logic",
        "title": "五元命题逻辑唯一解约束推演",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": sol,
        "grader": grade,
    }


# 4. Deductive Logic: Critical-Path DAG Scheduling
def _build_logic_dag_schedule(rng: random.Random) -> dict[str, Any]:
    """6-task project DAG with unlimited parallel workers -> compute exact minimum total duration (critical path)."""
    durs = {t: rng.randint(2, 9) for t in ("A", "B", "C", "D", "E", "F")}
    edges = [
        ("A", "C"),
        ("A", "D"),
        ("B", "D"),
        ("B", "E"),
        ("C", "F"),
        ("D", "F"),
        ("E", "F"),
    ]
    if rng.choice([True, False]):
        edges.append(("C", "E"))

    preds: dict[str, list[str]] = {t: [] for t in durs}
    for u, v in edges:
        preds[v].append(u)

    earliest_finish: dict[str, int] = {}
    for t in ("A", "B", "C", "D", "E", "F"):
        start = max((earliest_finish[p] for p in preds[t]), default=0)
        earliest_finish[t] = start + durs[t]
    makespan = max(earliest_finish.values())

    prompt = (
        "Six build jobs have durations (hours) and prerequisite dependencies. "
        "You have UNLIMITED parallel servers, so any jobs whose prerequisites are all finished can run simultaneously:\n"
        + "\n".join(
            f"- Job {t}: duration {durs[t]}h; prerequisites: {', '.join(preds[t]) if preds[t] else 'NONE'}"
            for t in ("A", "B", "C", "D", "E", "F")
        )
        + "\n\nWhat is the MINIMUM total time (in hours) to finish ALL six jobs (including Job F)?\n"
        'Return ONLY strict JSON: {"min_hours": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            got = int(obj.get("min_hours", -1))
        except Exception:
            got = -1
        if got == makespan:
            return 1.0, f"DAG 关键路径最短工期精确命中 ({makespan}h)"
        return 0.0, f"工期推演错误（答 {got}h，期 {makespan}h）"

    return {
        "id": "iq_logic_dag",
        "dimension": "deductive_logic",
        "title": "并行依赖图 (DAG) 关键路径排程",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": makespan,
        "grader": grade,
    }


# 5. Deductive Logic: Chinese Tiered Progressive Contract Math
def _build_bilingual_tiered_rebate(rng: random.Random) -> dict[str, Any]:
    """Chinese financial uppercase numbers + 3-tier progressive fee calculation."""
    tier1_lim = rng.choice([20, 30, 40])
    tier2_lim = tier1_lim + rng.choice([30, 40, 50])
    amt = tier2_lim + rng.randint(12, 35)
    r1, r2, r3 = rng.choice([(10, 20, 30), (5, 15, 25), (10, 15, 25)])
    # Fee is integer percentage applied progressively per bracket (in units of 100 yuan -> exact integer yuan!)
    total_yuan = amt * 100
    fee = (
        tier1_lim * 100 * r1 // 100
        + (tier2_lim - tier1_lim) * 100 * r2 // 100
        + (amt - tier2_lim) * 100 * r3 // 100
    )
    t1_cn = _int_to_cn_financial(tier1_lim)
    t2_cn = _int_to_cn_financial(tier2_lim)

    prompt = (
        "请按以下中文阶梯超额累进服务费规则计算精确应付费用（单位：元，整数）：\n"
        f"- 订单总额：{total_yuan} 元。\n"
        f"- 第一档：不超过「{t1_cn}佰元」（即 {tier1_lim*100} 元）的部分，费率 {r1}%；\n"
        f"- 第二档：超过「{t1_cn}佰元」至「{t2_cn}佰元」的部分，费率 {r2}%；\n"
        f"- 第三档：超过「{t2_cn}佰元」的部分，费率 {r3}%。\n"
        "注意：采用「超额累进」分段计费，而非全额适用最高档。\n"
        '请只返回严格 JSON：{"fee_yuan": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            got = int(round(float(obj.get("fee_yuan", -1))))
        except Exception:
            got = -1
        if got == fee:
            return 1.0, f"中文超额累进分段计费 100% 精确 ({fee} 元)"
        return 0.0, f"分段计费结果错（答 {got} 元，期 {fee} 元）"

    return {
        "id": "iq_bilingual_tiered",
        "dimension": "deductive_logic",
        "title": "中文财务大写与超额累进分段计算",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": fee,
        "grader": grade,
    }


# 6. Math Reasoning: Inclusion-Exclusion Exact Counting
def _build_math_combinatorics_ie(rng: random.Random) -> dict[str, Any]:
    n_max = rng.choice([420, 600, 720, 840, 960])
    a, b, c = rng.choice([(3, 5, 7), (4, 6, 9), (3, 7, 5), (5, 8, 6), (4, 5, 12)])
    exact = sum(1 for x in range(1, n_max + 1) if (x % a == 0 or x % b == 0) and (x % c != 0))

    prompt = (
        f"How many positive integers x in the inclusive range [1, {n_max}] satisfy BOTH conditions:\n"
        f"1. x is divisible by {a} OR divisible by {b} (or both), AND\n"
        f"2. x is NOT divisible by {c}?\n"
        'Return ONLY strict JSON: {"count": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            got = int(obj.get("count", -1))
        except Exception:
            got = -1
        if got == exact:
            return 1.0, f"容斥原理精确计数命中 ({exact})"
        return 0.0, f"容斥计数错误（答 {got}，期 {exact}）"

    return {
        "id": "iq_math_ie",
        "dimension": "math_reasoning",
        "title": "数论容斥原理精确计数",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": exact,
        "grader": grade,
    }


# 7. Math Reasoning: Modular Exponentiation & Remainder
def _build_math_modular_pow(rng: random.Random) -> dict[str, Any]:
    a = rng.choice([3, 5, 7, 11, 13])
    b = rng.randint(23, 59)
    c = rng.randint(17, 49)
    d = rng.randint(13, 41)
    m = rng.choice([17, 19, 23, 29, 31])
    while a % m == 0:
        a += 2
    exact = (pow(a, b, m) + c * d) % m

    prompt = (
        f"Compute the exact remainder when ({a}^{b} + {c} * {d}) is divided by {m}.\n"
        'Return ONLY strict JSON: {"remainder": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            got = int(obj.get("remainder", -1))
        except Exception:
            got = -1
        if got == exact:
            return 1.0, f"大指数模幂运算精确命中 ({exact})"
        return 0.0, f"模幂余数错误（答 {got}，期 {exact}）"

    return {
        "id": "iq_math_modpow",
        "dimension": "math_reasoning",
        "title": "大指数快速模幂余数推演",
        "difficulty": "hard",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": exact,
        "grader": grade,
    }


# 8. Math Reasoning: 6-Node Weighted Directed Shortest Path (Anti-Greedy Trap)
def _build_math_dijkstra_graph(rng: random.Random) -> dict[str, Any]:
    """Weighted graph where direct/greedy path is more expensive than a 4-hop indirect path."""
    w_sa = rng.randint(4, 7)
    w_sb = rng.randint(8, 12)
    w_ab = rng.randint(2, 4)
    w_ac = rng.randint(9, 14)
    w_bc = rng.randint(2, 4)
    w_bd = rng.randint(10, 15)
    w_cd = rng.randint(2, 4)
    w_dt = rng.randint(3, 6)
    w_ct = rng.randint(11, 16)
    w_at = rng.randint(19, 26)

    adj: dict[str, list[tuple[str, int]]] = {
        "S": [("A", w_sa), ("B", w_sb)],
        "A": [("B", w_ab), ("C", w_ac), ("T", w_at)],
        "B": [("C", w_bc), ("D", w_bd)],
        "C": [("D", w_cd), ("T", w_ct)],
        "D": [("T", w_dt)],
        "T": [],
    }
    dist: dict[str, int] = {"S": 0}
    pq = [(0, "S")]
    while pq:
        d, u = heapq.heappop(pq)
        if d > dist.get(u, 10**9):
            continue
        for v, w in adj[u]:
            nd = d + w
            if nd < dist.get(v, 10**9):
                dist[v] = nd
                heapq.heappush(pq, (nd, v))
    exact = dist["T"]

    edge_lines = [f"  {u} -> {v} : weight {w}" for u, nbrs in adj.items() for v, w in nbrs]
    prompt = (
        "Find the exact MINIMUM total weight of a directed path from node S to node T in this weighted directed graph:\n"
        + "\n".join(edge_lines)
        + '\n\nReturn ONLY strict JSON: {"min_cost": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            got = int(obj.get("min_cost", -1))
        except Exception:
            got = -1
        if got == exact:
            return 1.0, f"有向加权图最短路精确命中 ({exact})"
        return 0.0, f"最短路计算错（答 {got}，期 {exact}）"

    return {
        "id": "iq_math_dijkstra",
        "dimension": "math_reasoning",
        "title": "有向加权图反贪心最短路推演",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": exact,
        "grader": grade,
    }


# 9. Code Tracing: Python Closure Late-Binding + Mutable Default Arg
def _build_code_trace_closure_mutable(rng: random.Random) -> dict[str, Any]:
    k1 = rng.randint(2, 5)
    k2 = rng.randint(1, 4)
    n_loop = rng.choice([3, 4])

    code = (
        f"def acc(v, box=[]):\n"
        f"    box.append(v)\n"
        f"    return sum(box)\n\n"
        f"fns = [lambda x: x * i + {k1} for i in range(1, {n_loop + 1})]\n"
        f"vals = [f({k2}) for f in fns]\n"
        f"r1 = acc(vals[0])\n"
        f"r2 = acc(vals[-1])\n"
        f"r3 = acc(len(vals), [10])\n"
        f"result = r1 + r2 + r3\n"
    )
    ns: dict[str, Any] = {}
    exec(compile(code, "<trace_closure>", "exec"), {"__builtins__": _SAFE_BUILTINS}, ns)
    expected = int(ns["result"])

    prompt = (
        "Trace this Python 3 snippet carefully (pay attention to closure late-binding and mutable default arguments!):\n\n"
        f"```python\n{code}```\n\n"
        'What is the exact integer value of `result`? Return ONLY strict JSON: {"result": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            got = int(obj.get("result", -999999))
        except Exception:
            got = -999999
        if got == expected:
            return 1.0, f"Python 闭包延迟绑定与可变默认参数精准追踪 ({expected})"
        return 0.0, f"代码追踪结果错（答 {got}，期 {expected}）"

    return {
        "id": "iq_code_closure",
        "dimension": "code_tracing",
        "title": "Python 闭包延迟绑定与可变默认参数追踪",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


# 10. Code Engineering (AST Sandbox): Dynamic Programming Min Cost with Jump Penalty
def _build_code_algo_dp_sandbox(rng: random.Random) -> dict[str, Any]:
    jump_pen = rng.randint(3, 9)
    max_step = rng.choice([2, 3])

    def ref_dp(costs: list[int], pen: int) -> int:
        n = len(costs)
        if n == 0:
            return 0
        if n == 1:
            return costs[0]
        dp = [10**18] * n
        dp[0] = costs[0]
        for i in range(1, n):
            best = dp[i - 1]
            for s in range(2, max_step + 1):
                if i - s >= 0:
                    cand = dp[i - s] + pen * (s - 1)
                    if cand < best:
                        best = cand
            dp[i] = best + costs[i]
        return dp[-1]

    tests = [
        ([5], jump_pen),
        ([4, 10, 2, 15, 3], jump_pen),
        ([1, 20, 20, 1, 20, 20, 1], jump_pen),
        ([8, -3, 12, -5, 4, 2], jump_pen),
        ([2, 2, 2, 2, 2, 2], jump_pen),
        ([rng.randint(-4, 25) for _ in range(9)], jump_pen + 2),
    ]

    prompt = (
        f"Write a pure Python function `def min_journey_cost(costs, pen):` (NO imports).\n"
        f"Rules:\n"
        f"- `costs` is a list of integers (may include negative numbers!). If empty, return 0; if len==1, return costs[0].\n"
        f"- You start at index 0 (paying `costs[0]`) and must finish at index `len(costs) - 1`.\n"
        f"- From index `i`, you can move to `i + s` for any `s` in `1..{max_step}` (staying inside bounds).\n"
        f"- Moving by `s = 1` has 0 extra penalty; moving by `s >= 2` adds an extra jump penalty of `pen * (s - 1)` PLUS `costs[i + s]`.\n"
        f"- Return the exact MINIMUM total cost to reach the last index.\n"
        "Return ONLY the Python function inside a ```python code block."
    )

    def grade(raw: str) -> tuple[float, str]:
        code = _extract_func_code(raw, "min_journey_cost")
        safe, reason = _ast_is_safe_pure_python(code)
        if not safe:
            return 0.0, f"沙箱拦截: {reason}"
        ns: dict[str, Any] = {}
        try:
            exec(compile(code, "<iq_dp>", "exec"), {"__builtins__": _SAFE_BUILTINS}, ns)
            fn = ns.get("min_journey_cost")
            if not callable(fn):
                return 0.0, "未定义函数 min_journey_cost"
            passed = sum(1 for arr, p in tests if fn(list(arr), p) == ref_dp(arr, p))
        except Exception as exc:
            return 0.0, f"运行报错: {type(exc).__name__}: {exc}"
        if passed == len(tests):
            return 1.0, f"AST 安全沙箱动态规划 6/6 隐藏单测全通过！"
        return round((passed / len(tests)) * 0.65, 2), f"动态规划单测通过 {passed}/{len(tests)}"

    return {
        "id": "iq_code_dp_sandbox",
        "dimension": "code_bugfix",
        "title": "AST 沙箱可执行算法：带跳步惩罚动态规划 (6组单测)",
        "difficulty": "hard",
        "max_score": 16.0,
        "prompt": prompt,
        "expected": "passes 6/6 hidden DP unit tests",
        "grader": grade,
    }


# 11. Engineering SQL (SQLite :memory:): Department Filter + Window Rank / Aggregation
def _build_sqlite_dept_summary(rng: random.Random) -> dict[str, Any]:
    """Second executable read-only SQLite challenge: HAVING + AVG rounding + tie-break ORDER BY."""
    depts = ["Core", "Data", "Infra", "Sec"]
    min_emp = 2
    rows: list[tuple[int, str, str, int]] = []
    eid = 1
    # Ensure Core, Data, Infra have >= 2 employees, Sec has only 1 employee (filtered out by HAVING!)
    counts = {"Core": 3, "Data": 3, "Infra": 2, "Sec": 1}
    for d in depts:
        for j in range(counts[d]):
            sal = rng.choice([120, 140, 150, 180, 200, 210, 240, 260])
            rows.append((eid, f"E{eid}", d, sal))
            eid += 1

    def _seed() -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE staff (id INTEGER PRIMARY KEY, name TEXT, dept TEXT, salary INTEGER)")
        conn.executemany("INSERT INTO staff VALUES (?, ?, ?, ?)", rows)
        return conn

    ref_sql = (
        f"SELECT dept, MAX(salary) AS top_sal, SUM(salary) AS total_sal "
        f"FROM staff GROUP BY dept HAVING COUNT(*) >= {min_emp} "
        f"ORDER BY top_sal DESC, total_sal DESC, dept ASC"
    )
    c_ref = _seed()
    expected = [(str(r[0]), int(r[1]), int(r[2])) for r in c_ref.execute(ref_sql).fetchall()]
    c_ref.close()

    prompt = (
        "Write a single standard SQLite SELECT query for table `staff(id INTEGER, name TEXT, dept TEXT, salary INTEGER)`:\n"
        f"1. Keep ONLY departments having at least {min_emp} employees.\n"
        "2. Return columns `(dept, top_sal, total_sal)` where `top_sal = MAX(salary)` and `total_sal = SUM(salary)`.\n"
        "3. Order by `top_sal DESC, total_sal DESC, dept ASC`.\n"
        'Return ONLY strict JSON: {"sql": "SELECT ..."}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        sql = str(obj.get("sql", "")).strip() if isinstance(obj, dict) else ""
        if not sql:
            m = re.findall(r"```(?:sql)?\s*(SELECT.*?)```", raw or "", flags=re.S | re.I)
            sql = m[-1].strip() if m else ""
        sql = sql.rstrip(";").strip()
        if not sql or not sql.upper().startswith(("SELECT", "WITH")) or ";" in sql:
            return 0.0, "未提取到合法只读 SELECT 查询"
        conn = _seed()
        try:
            allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
            conn.set_authorizer(lambda a, *_: sqlite3.SQLITE_OK if a in allowed else sqlite3.SQLITE_DENY)
            got = [(str(r[0]), int(r[1]), int(r[2])) for r in conn.execute(sql).fetchmany(30)]
            if got == expected:
                return 1.0, f"SQLite 沙箱分组聚合 + HAVING 100% 匹配 ({len(expected)} 部门)"
            return 0.0, f"SQL 结果不匹配（实 {got}，期 {expected}）"
        except Exception as exc:
            return 0.0, f"SQL 执行失败: {exc}"
        finally:
            conn.close()

    return {
        "id": "iq_sqlite_having",
        "dimension": "engineering_sql",
        "title": "可执行 SQLite 沙箱：GROUP BY / HAVING 与多键排序",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


# 12. Spatial 3D Simulation: Rolling Standard 6-Face Die
def _build_spatial_rolling_die(rng: random.Random) -> dict[str, Any]:
    """Simulate an 8-roll 3D standard die orientation state machine (opposite faces sum to 7)."""
    # Start standard orientation: top=1, north=2, east=3 (so bottom=6, south=5, west=4)
    top, north, east = rng.choice([(1, 2, 3), (2, 3, 1), (3, 1, 2), (1, 4, 2)])
    moves = [rng.choice(["N", "S", "E", "W"]) for _ in range(8)]

    t, n, e = top, north, east
    for mv in moves:
        b, s, w = 7 - t, 7 - n, 7 - e
        if mv == "N":
            t, n, e = s, t, e
        elif mv == "S":
            t, n, e = n, b, e
        elif mv == "E":
            t, n, e = w, n, t
        elif mv == "W":
            t, n, e = e, n, b
    expected = {"top": t, "north": n, "east": e}

    prompt = (
        "A standard 6-sided die (opposite faces always sum to 7: 1↔6, 2↔5, 3↔4) sits on a flat table.\n"
        f"Initial orientation: TOP = {top}, NORTH = {north}, EAST = {east} "
        f"(so BOTTOM = {7-top}, SOUTH = {7-north}, WEST = {7-east}).\n"
        "Each roll tips the die 90 degrees onto the adjacent face in that direction:\n"
        "- Roll N: old SOUTH becomes new TOP; old TOP becomes new NORTH; EAST stays unchanged.\n"
        "- Roll S: old NORTH becomes new TOP; old BOTTOM becomes new NORTH; EAST stays unchanged.\n"
        "- Roll E: old WEST becomes new TOP; old TOP becomes new EAST; NORTH stays unchanged.\n"
        "- Roll W: old EAST becomes new TOP; old BOTTOM becomes new EAST; NORTH stays unchanged.\n\n"
        f"Execute this exact sequence of 8 rolls in order: {moves}\n"
        'Return ONLY strict JSON: {"top": <int>, "north": <int>, "east": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        try:
            gt, gn, ge = int(obj.get("top", -1)), int(obj.get("north", -1)), int(obj.get("east", -1))
        except Exception:
            gt, gn, ge = -1, -1, -1
        if (gt, gn, ge) == (t, n, e):
            return 1.0, f"三维骰子 8 步滚动姿态推演 100% 精确 (top={t}, north={n}, east={e})"
        if gt == t:
            return 0.5, f"顶面 {t} 正确，但北/东朝向错误（答 {gn},{ge}，期 {n},{e}）"
        return 0.0, f"三维姿态错（答 {gt},{gn},{ge}，期 {t},{n},{e}）"

    return {
        "id": "iq_spatial_die3d",
        "dimension": "spatial_sim",
        "title": "三维骰子 8 步滚动空间姿态推演",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


# 13. Instruction Following: Multi-Constraint Structured Record Filter & Checksum
def _build_instruction_record_transform(rng: random.Random) -> dict[str, Any]:
    thresh = rng.choice([50, 60, 70])
    items = [
        ("alpha", rng.randint(thresh + 5, 95)),
        ("bravo", rng.randint(15, thresh - 5)),
        ("gamma", rng.randint(thresh + 10, 99)),
        ("delta", rng.randint(thresh + 1, 92)),
        ("omega", rng.randint(10, thresh - 8)),
    ]
    rng.shuffle(items)
    kept = sorted([(k.upper(), v) for k, v in items if v >= thresh], key=lambda x: (-x[1], x[0]))
    joined = "|".join(f"{k}:{v}" for k, v in kept)
    checksum = sum(v for _, v in kept)

    prompt = (
        f"Transform these records strictly following ALL 5 rules:\n"
        + "\n".join(f"- {k} = {v}" for k, v in items)
        + f"\n\nRules:\n"
        f"1. Keep ONLY items with value >= {thresh}.\n"
        f"2. Convert kept names to UPPERCASE.\n"
        f"3. Sort by value DESCENDING (tie-break alphabetically).\n"
        f"4. Join as `NAME:VALUE` separated by `|` with NO spaces.\n"
        f"5. Compute `sum_kept` (integer sum of kept values) and `count` (number of kept items).\n"
        'Return ONLY strict JSON with exact keys: {"joined": "...", "sum_kept": <int>, "count": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        ok_j = str(obj.get("joined", "")).strip() == joined
        try:
            ok_s = int(obj.get("sum_kept", -1)) == checksum
            ok_c = int(obj.get("count", -1)) == len(kept)
        except Exception:
            ok_s = ok_c = False
        if ok_j and ok_s and ok_c:
            return 1.0, "5 重结构化筛选排序与校验和约束全通过"
        hits = int(ok_j) + int(ok_s) + int(ok_c)
        return round(hits / 3.0 * 0.6, 2), f"结构化遵循命中 {hits}/3（期 joined={joined}, sum={checksum}）"

    return {
        "id": "iq_instr_transform",
        "dimension": "instruction_following",
        "title": "五重结构化筛选排序与校验和遵循",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": {"joined": joined, "sum_kept": checksum, "count": len(kept)},
        "grader": grade,
    }


# 14. RAG Faithfulness: Two-Memo Temporal Override + Zero-Hallucination
def _build_rag_temporal_amendment(rng: random.Random) -> dict[str, Any]:
    old_limit = rng.choice([500, 800, 1000])
    new_limit = rng.choice([250, 350, 450])
    keep_region = rng.choice(["OSLO-2", "ZURICH-4", "OSAKA-7"])
    old_port = rng.choice([8080, 8443])
    new_port = rng.choice([9123, 9447, 9781])

    doc = (
        "=== DOCUMENT 1: CoreOps Policy v1 (Effective Jan 10, 2026) ===\n"
        f"- Max batch size: {old_limit} items.\n"
        f"- Primary archival region: {keep_region}.\n"
        f"- Internal sync port: {old_port}.\n\n"
        "=== DOCUMENT 2: Policy Amendment v2 (Effective Aug 18, 2026) ===\n"
        "This amendment supersedes ONLY the explicitly listed fields from v1; all unmentioned v1 fields remain active.\n"
        f"- Max batch size is REDUCED to {new_limit} items.\n"
        f"- Internal sync port is CHANGED to {new_port}.\n"
        "(No cold-storage encryption cipher name is specified in either document.)\n"
    )

    prompt = (
        "Using ONLY the two internal memos below, determine the CURRENT effective configuration as of late 2026. "
        'If a field is not defined in either memo, you MUST output "NOT_SPECIFIED".\n\n'
        f"{doc}\n"
        'Return ONLY strict JSON: {"max_batch_size": <int>, "archival_region": "<str>", '
        '"sync_port": <int>, "cold_cipher": "<str or NOT_SPECIFIED>"}'
    )
    expected = {
        "max_batch_size": new_limit,
        "archival_region": keep_region,
        "sync_port": new_port,
        "cold_cipher": "NOT_SPECIFIED",
    }

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析 JSON"
        hits = 0
        try:
            if int(obj.get("max_batch_size", -1)) == new_limit:
                hits += 1
        except Exception:
            pass
        if str(obj.get("archival_region", "")).strip().upper() == keep_region:
            hits += 1
        try:
            if int(obj.get("sync_port", -1)) == new_port:
                hits += 1
        except Exception:
            pass
        if str(obj.get("cold_cipher", "")).strip().upper() == "NOT_SPECIFIED":
            hits += 1
        if hits == 4:
            return 1.0, "双文档时间覆盖合并 + 零幻觉拒答 4/4 全对"
        return round(hits / 4.0 * 0.7, 2), f"文档冲突合并命中 {hits}/4（期 {expected}）"

    return {
        "id": "iq_rag_amendment",
        "dimension": "rag_faithfulness",
        "title": "新旧双文档冲突覆盖与零幻觉拒答",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


def get_extended_iq_builders() -> dict[str, Any]:
    """Return mapping of all 14 extended v11.2 dynamic IQ builders."""
    return {
        "simpson": _build_anti_bias_simpson_paradox,
        "harmonic": _build_anti_bias_harmonic_speed,
        "sat5": _build_logic_propositional_sat,
        "dag": _build_logic_dag_schedule,
        "tiered_cn": _build_bilingual_tiered_rebate,
        "comb_ie": _build_math_combinatorics_ie,
        "modpow": _build_math_modular_pow,
        "dijkstra": _build_math_dijkstra_graph,
        "closure": _build_code_trace_closure_mutable,
        "dp_sandbox": _build_code_algo_dp_sandbox,
        "sql_having": _build_sqlite_dept_summary,
        "die3d": _build_spatial_rolling_die,
        "instr_xform": _build_instruction_record_transform,
        "rag_amend": _build_rag_temporal_amendment,
    }
