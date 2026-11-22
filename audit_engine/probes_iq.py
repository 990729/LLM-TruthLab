"""Anti-Contamination Dynamic IQ Evaluation Engine.

Generates fresh, seed-controlled reasoning tasks across 6 cognitive dimensions
with 100% programmatic, mathematically verified ground truth (no memorized
riddles, no subjective LLM-as-a-judge).
"""

from __future__ import annotations

import ast
import concurrent.futures
import itertools
import json
import random
import re
import sqlite3
from fractions import Fraction
from typing import Any, Callable

from .client import RelayClient
from .models import AuditConfig, EvidenceItem, IQQuestionResult, IQSummary

ProgressCb = Callable[[str, str], None]


_DIMENSION_LABELS: dict[str, str] = {
    "anti_bias": "抗惯性认知陷阱",
    "deductive_logic": "多步约束逻辑",
    "math_reasoning": "精确数理推演",
    "code_tracing": "代码静态追踪",
    "code_bugfix": "实战代码与补丁",
    "engineering_sql": "SQL 数据库实战",
    "spatial_sim": "二维空间状态推演",
    "instruction_following": "多重硬约束遵循",
    "rag_faithfulness": "私有文档防幻觉",
    "long_context_needle": "长文多跳检索",
}


def _extract_json_obj(text: str) -> dict[str, Any] | None:
    """Extract the last/best JSON object from model output."""
    s = (text or "").strip()
    s = re.sub(r"<think>.*?</think>", "", s, flags=re.S | re.I).strip()
    # Direct parse
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    # Fenced code block
    blocks = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", s, flags=re.S | re.I)
    for b in reversed(blocks):
        try:
            obj = json.loads(b)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    # Balanced brace scan from the end
    starts = [m.start() for m in re.finditer(r"\{", s)]
    for st in reversed(starts):
        depth = 0
        for idx in range(st, len(s)):
            if s[idx] == "{":
                depth += 1
            elif s[idx] == "}":
                depth -= 1
                if depth == 0:
                    cand = s[st : idx + 1]
                    try:
                        obj = json.loads(cand)
                        if isinstance(obj, dict):
                            return obj
                    except Exception:
                        break
    return None


def _extract_last_int(text: str) -> int | None:
    s = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S | re.I)
    obj = _extract_json_obj(s)
    if obj:
        for k in ("answer", "result", "value", "day", "trips", "cost", "x"):
            if k in obj:
                try:
                    return int(float(str(obj[k]).strip()))
                except Exception:
                    pass
    nums = re.findall(r"-?\d+", s)
    if nums:
        try:
            return int(nums[-1])
        except Exception:
            return None
    return None


def _extract_last_number(text: str) -> float | None:
    s = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S | re.I)
    obj = _extract_json_obj(s)
    if obj:
        for k in ("answer", "result", "value", "cost"):
            if k in obj:
                try:
                    return float(str(obj[k]).strip().replace("$", ""))
                except Exception:
                    pass
    nums = re.findall(r"-?\d+(?:\.\d+)?", s)
    if nums:
        try:
            return float(nums[-1])
        except Exception:
            return None
    return None


# ======================================================================
# Dimension 1: Anti-Bias Cognitive Reflection (Dynamic Twisted Traps)
# ======================================================================


def _build_anti_bias_crystal(rng: random.Random) -> dict[str, Any]:
    """Twisted lily-pad / exponential doubling problem (catches memorized N-1!)."""
    full_day = rng.randint(24, 68)
    # Twist: ask for 1/8 or 1/16 of the pond, NOT 1/2!
    power = rng.choice([3, 4])  # 1/8 -> full_day - 3; 1/16 -> full_day - 4
    denom = 2**power
    expected = full_day - power
    prompt = (
        f"A colony of glowing algae in a circular tank doubles its total area every single day. "
        f"On Day {full_day}, the algae completely covers the entire tank (100%). "
        f"On which exact day did the algae cover exactly 1/{denom} of the tank? "
        'Think carefully and end your response with strict JSON: {"answer": <integer>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        ans = _extract_last_int(raw)
        if ans == expected:
            return 1.0, f"精确答对 Day {expected}（未落入 1/{denom} 线性除法的直觉陷阱）"
        return 0.0, f"回答 {ans}，正确答案应为 {expected}（{full_day} - {power}）"

    return {
        "id": "iq_antibias_exp",
        "dimension": "anti_bias",
        "title": "指数倍增反直觉变体",
        "difficulty": "medium",
        "max_score": 10.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


def _build_anti_bias_crossing(rng: random.Random) -> dict[str, Any]:
    """Twisted river crossing where boat fits all items at once (catches memorized '7 trips')."""
    boat_cap = rng.randint(4, 6)
    animal_a = rng.choice(["wolf", "fox", "leopard"])
    animal_b = rng.choice(["goat", "rabbit", "duck"])
    item_c = rng.choice(["cabbage", "carrots", "grain"])
    prompt = (
        f"A farmer needs to take a {animal_a}, a {animal_b}, and a crate of {item_c} across a river. "
        f"He owns a sturdy motorboat that can safely carry the farmer PLUS up to {boat_cap} passengers/items at the same time. "
        f"What is the MINIMUM number of one-way river crossings required to move the farmer, the {animal_a}, "
        f"the {animal_b}, and the {item_c} to the far bank? "
        'End your response with strict JSON: {"trips": <integer>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        ans = _extract_last_int(raw)
        if ans == 1:
            return 1.0, "识破经典过河题变体陷阱，正确得出仅需 1 次渡河"
        return 0.0, f"回答 {ans}，落入背诵经典过河题惯性陷阱（船可一次装下全部，答案=1）"

    return {
        "id": "iq_antibias_river",
        "dimension": "anti_bias",
        "title": "经典过河题反转陷阱",
        "difficulty": "medium",
        "max_score": 8.0,
        "prompt": prompt,
        "expected": 1,
        "grader": grade,
    }


def _build_anti_bias_pricing(rng: random.Random) -> dict[str, Any]:
    """Dynamic twisted Bat-and-Ball with multiplier + offset."""
    casing = rng.randint(13, 47)
    mult = rng.choice([2, 3])
    diff = rng.randint(15, 65)
    # sensor = mult * casing + diff
    sensor = mult * casing + diff
    total = sensor + casing
    prompt = (
        f"A precision optical sensor and its titanium casing together cost ${total}. "
        f"The sensor costs ${diff} more than {mult} times the price of the casing. "
        f"What is the exact price of the casing in dollars? "
        'End your response with strict JSON: {"cost": <number>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        ans = _extract_last_number(raw)
        if ans is not None and abs(ans - casing) < 1e-6:
            return 1.0, f"精确解出外壳价格 ${casing}"
        return 0.0, f"回答 {ans}，正确答案应为 {casing}"

    return {
        "id": "iq_antibias_price",
        "dimension": "anti_bias",
        "title": "球拍与球代数变体陷阱",
        "difficulty": "medium",
        "max_score": 8.0,
        "prompt": prompt,
        "expected": casing,
        "grader": grade,
    }


# ======================================================================
# Dimension 2: Multi-Step Constraint Deductive Logic (Unique-Solution Verified)
# ======================================================================


def _build_logic_grid(rng: random.Random) -> dict[str, Any]:
    """Generate a 4-seat ordering + color assignment puzzle with verified UNIQUE solution."""
    names_pool = ["Alice", "Bruno", "Chloe", "Dante", "Elena", "Felix", "Grace", "Hugo"]
    colors_pool = ["Amber", "Cobalt", "Emerald", "Crimson", "Ivory", "Violet"]
    names = rng.sample(names_pool, 4)
    colors = rng.sample(colors_pool, 4)

    # True assignment: seat 1..4 -> (name, color)
    seat_names = list(names)
    rng.shuffle(seat_names)
    seat_colors = list(colors)
    rng.shuffle(seat_colors)

    pos_of_name = {n: i + 1 for i, n in enumerate(seat_names)}
    pos_of_color = {c: i + 1 for i, c in enumerate(seat_colors)}
    color_of_name = {seat_names[i]: seat_colors[i] for i in range(4)}

    # Build a rich clue set and verify unique solution by exhaustive search
    n0, n1, n2, n3 = seat_names[0], seat_names[1], seat_names[2], seat_names[3]
    c0, c1, c2, c3 = seat_colors[0], seat_colors[1], seat_colors[2], seat_colors[3]

    # Candidate clues guaranteed true for the hidden assignment
    clue_specs = [
        (
            f"{n1} sits immediately to the right of {n0} (i.e., seat({n1}) = seat({n0}) + 1).",
            lambda sn, sc, a=n0, b=n1: sn.index(b) == sn.index(a) + 1,
        ),
        (
            f"{n3} sits somewhere to the right of {n2}, and {n3} does NOT sit in Seat 2.",
            lambda sn, sc, a=n2, b=n3: sn.index(b) > sn.index(a) and sn.index(b) != 1,
        ),
        (
            f"The person wearing {c0} sits in Seat 1.",
            lambda sn, sc, col=c0: sc[0] == col,
        ),
        (
            f"{n2} wears {c2}.",
            lambda sn, sc, nm=n2, col=c2: sc[sn.index(nm)] == col,
        ),
        (
            f"The person wearing {c1} sits immediately to the left of the person wearing {c2}.",
            lambda sn, sc, ca=c1, cb=c2: sc.index(ca) + 1 == sc.index(cb),
        ),
        (
            f"{n0} does NOT wear {c3}, and {n0} sits to the left of {n2}.",
            lambda sn, sc, nm=n0, nm2=n2, col=c3: sc[sn.index(nm)] != col and sn.index(nm) < sn.index(nm2),
        ),
        (
            f"The person in Seat 4 wears {c3}.",
            lambda sn, sc, col=c3: sc[3] == col,
        ),
    ]

    # Verify uniqueness strictly via exhaustive search over 24 * 24 = 576 states
    solutions = []
    for sn in itertools.permutations(names):
        for sc in itertools.permutations(colors):
            if all(fn(sn, sc) for _, fn in clue_specs):
                solutions.append((sn, sc))

    # If multiple solutions exist (rare edge case), add one disambiguating clue
    if len(solutions) != 1:
        clue_specs.append(
            (
                f"{n1} wears {c1}.",
                lambda sn, sc, nm=n1, col=c1: sc[sn.index(nm)] == col,
            )
        )
        solutions = [
            (sn, sc)
            for sn in itertools.permutations(names)
            for sc in itertools.permutations(colors)
            if all(fn(sn, sc) for _, fn in clue_specs)
        ]

    assert len(solutions) == 1, f"Logic grid uniqueness invariant violated: {len(solutions)}"

    shuffled_clues = [txt for txt, _ in clue_specs]
    rng.shuffle(shuffled_clues)

    clue_lines = "\n".join(f"{i+1}. {c}" for i, c in enumerate(shuffled_clues))
    expected_map = {seat_names[i]: {"seat": i + 1, "color": seat_colors[i]} for i in range(4)}

    prompt = (
        f"Four people ({', '.join(names)}) sit in a row in Seats 1, 2, 3, and 4 (from left to right). "
        f"Each wears a distinct color ({', '.join(colors)}). All of the following clues are true:\n"
        f"{clue_lines}\n\n"
        "Deduce the unique seat (1..4) and color for every person. "
        f'End your response with strict JSON mapping each name to seat and color, e.g.: '
        f'{{"{names[0]}": {{"seat": 1, "color": "{colors[0]}"}}, ...}}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析的 JSON 逻辑推演结果"
        correct_fields = 0
        total_fields = 8
        for nm, exp in expected_map.items():
            # Case-insensitive key lookup
            entry = None
            for k, v in obj.items():
                if k.strip().lower() == nm.lower() and isinstance(v, dict):
                    entry = v
                    break
            if entry:
                try:
                    if int(entry.get("seat", -1)) == exp["seat"]:
                        correct_fields += 1
                except Exception:
                    pass
                if str(entry.get("color", "")).strip().lower() == exp["color"].lower():
                    correct_fields += 1
        frac = correct_fields / total_fields
        if frac == 1.0:
            return 1.0, "全部 4 人的座位与颜色约束推演 100% 精确"
        return round(frac * 0.6, 3), f"仅命中 {correct_fields}/{total_fields} 项约束字段"

    return {
        "id": "iq_logic_grid",
        "dimension": "deductive_logic",
        "title": "四元唯一解约束逻辑网格",
        "difficulty": "hard",
        "max_score": 16.0,
        "prompt": prompt,
        "expected": expected_map,
        "grader": grade,
    }


def _build_knights_knaves(rng: random.Random) -> dict[str, Any]:
    """Generate a 4-person Knights (always true) & Knaves (always false) puzzle with unique solution."""
    people = rng.sample(["Kai", "Lina", "Milo", "Nora", "Omar", "Pia"], 4)
    A, B, C, D = people

    # Pick a hidden truth vector that isn't all-true or all-false
    truths = [rng.choice([True, False]) for _ in range(4)]
    if all(truths) or not any(truths):
        truths[0] = True
        truths[1] = False

    tA, tB, tC, tD = truths
    # Construct statements that match the hidden truth assignment AND guarantee uniqueness:
    # A says: "B is a Knight if and only if C is a Knave" -> holds iff (tB != tC)
    # Wait: make each statement's truth value EQUAL to the speaker's own knighthood!
    # Statement 1 (A): evaluates to True iff tA is True.
    s1_cond_true = (tB != tC)
    if s1_cond_true == tA:
        s1_text = f'{A} says: "Exactly one of {B} and {C} is a Knight."'
        s1_fn = lambda v: v[0] == (v[1] != v[2])
    else:
        s1_text = f'{A} says: "{B} and {C} are of the SAME type (both Knights or both Knaves)."'
        s1_fn = lambda v: v[0] == (v[1] == v[2])

    # Statement 2 (B): speaks about C and D
    s2_cond_true = (tC and not tD)
    if s2_cond_true == tB:
        s2_text = f'{B} says: "{C} is a Knight and {D} is a Knave."'
        s2_fn = lambda v: v[1] == (v[2] and not v[3])
    else:
        s2_text = f'{B} says: "It is NOT true that ({C} is a Knight and {D} is a Knave)."'
        s2_fn = lambda v: v[1] == (not (v[2] and not v[3]))

    # Statement 3 (C): speaks about count of Knights among all 4
    k_count = sum(1 for x in truths if x)
    if tC:
        s3_text = f'{C} says: "There are exactly {k_count} Knights among the four of us."'
        s3_fn = lambda v, kc=k_count: v[2] == (sum(v) == kc)
    else:
        wrong_k = (k_count + 1) % 4 or 1
        if wrong_k == k_count:
            wrong_k = 2
        s3_text = f'{C} says: "There are exactly {wrong_k} Knights among the four of us."'
        s3_fn = lambda v, wk=wrong_k: v[2] == (sum(v) == wk)

    # Statement 4 (D): speaks about A
    if tD == (not tA):
        s4_text = f'{D} says: "{A} is a Knave."'
        s4_fn = lambda v: v[3] == (not v[0])
    else:
        s4_text = f'{D} says: "{A} is a Knight."'
        s4_fn = lambda v: v[3] == v[0]

    # Verify uniqueness across all 16 truth assignments
    sols = [
        v
        for v in itertools.product([True, False], repeat=4)
        if s1_fn(v) and s2_fn(v) and s3_fn(v) and s4_fn(v)
    ]
    extra_fact = ""
    if len(sols) != 1:
        # Pin one differentiating fact so solution is strictly unique
        extra_fact = f"\nExternal verified fact: {D} is a {'Knight' if tD else 'Knave'}."
        sols = [v for v in sols if v[3] == tD]
        if len(sols) != 1:
            extra_fact += f" Also, {B} is a {'Knight' if tB else 'Knave'}."
            sols = [v for v in sols if v[1] == tB]

    assert len(sols) == 1, f"Knights/Knaves uniqueness failed: {len(sols)}"
    expected = {people[i]: ("Knight" if truths[i] else "Knave") for i in range(4)}

    prompt = (
        f"On an island, every resident is either a Knight (always tells the truth) or a Knave (always lies). "
        f"Four residents ({A}, {B}, {C}, {D}) make the following statements:\n"
        f"- {s1_text}\n- {s2_text}\n- {s3_text}\n- {s4_text}{extra_fact}\n\n"
        "Determine the unique identity (Knight or Knave) of each resident. "
        f'End your response with strict JSON: {{"{A}": "Knight|Knave", "{B}": "Knight|Knave", "{C}": "Knight|Knave", "{D}": "Knight|Knave"}}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析的 JSON 身份判定"
        hits = 0
        for p, exp in expected.items():
            for k, v in obj.items():
                if k.strip().lower() == p.lower():
                    if str(v).strip().lower() == exp.lower():
                        hits += 1
                    break
        if hits == 4:
            return 1.0, "4 人真话/假话布尔逻辑系统全部精确解出"
        return round((hits / 4.0) * 0.4, 3), f"仅答对 {hits}/4 个角色身份"

    return {
        "id": "iq_logic_knights",
        "dimension": "deductive_logic",
        "title": "四元真话/假话布尔逻辑推演",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


# ======================================================================
# Dimension 3: Symbolic & Modular Math Reasoning
# ======================================================================


def _build_math_crt(rng: random.Random) -> dict[str, Any]:
    """Chinese Remainder Theorem + threshold constraint (fresh every run)."""
    m1, m2, m3 = 5, 7, 9  # pairwise coprime, product = 315
    target = rng.randint(420, 980)
    r1, r2, r3 = target % m1, target % m2, target % m3
    # Ask for the smallest integer strictly greater than lower_bound
    lower_bound = target - rng.randint(15, 290)
    # Compute true smallest x > lower_bound matching all 3 congruences
    x = lower_bound + 1
    while not (x % m1 == r1 and x % m2 == r2 and x % m3 == r3):
        x += 1

    prompt = (
        f"Find the SMALLEST integer x strictly greater than {lower_bound} that satisfies ALL three conditions:\n"
        f"1) x mod {m1} = {r1}\n"
        f"2) x mod {m2} = {r2}\n"
        f"3) x mod {m3} = {r3}\n"
        'Show your calculation briefly and end with strict JSON: {"x": <integer>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        ans = _extract_last_int(raw)
        if ans == x:
            return 1.0, f"中国剩余定理 + 下界约束精确解出 x = {x}"
        return 0.0, f"回答 {ans}，正确答案应为 {x}"

    return {
        "id": "iq_math_crt",
        "dimension": "math_reasoning",
        "title": "同余方程组（中国剩余定理）",
        "difficulty": "hard",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": x,
        "grader": grade,
    }


def _build_math_bayes(rng: random.Random) -> dict[str, Any]:
    """Exact conditional probability (Bayes theorem) with reduced fraction answer."""
    r1 = rng.randint(2, 6)
    b1 = rng.randint(3, 7)
    r2 = rng.randint(3, 7)
    b2 = rng.randint(2, 6)
    if Fraction(r1, r1 + b1) == Fraction(r2, r2 + b2):
        r2 += 1
    # Urn A chosen with prob 1/3, Urn B with prob 2/3
    p_red_a = Fraction(r1, r1 + b1)
    p_red_b = Fraction(r2, r2 + b2)
    p_a_and_red = Fraction(1, 3) * p_red_a
    p_b_and_red = Fraction(2, 3) * p_red_b
    ans_frac = p_a_and_red / (p_a_and_red + p_b_and_red)
    expected_str = f"{ans_frac.numerator}/{ans_frac.denominator}"

    prompt = (
        f"There are two opaque boxes:\n"
        f"- Box A contains {r1} red balls and {b1} blue balls.\n"
        f"- Box B contains {r2} red balls and {b2} blue balls.\n"
        f"You choose Box A with probability 1/3, and Box B with probability 2/3. "
        f"Then you draw 1 ball uniformly at random from the chosen box, and it turns out to be RED. "
        f"What is the exact posterior probability that you chose Box A? "
        f'Express the answer as a fully reduced fraction "numerator/denominator" inside strict JSON: {{"answer": "p/q"}}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        cand = str(obj.get("answer", "")) if obj else raw
        m = re.search(r"(\d+)\s*/\s*(\d+)", cand)
        if m:
            try:
                got = Fraction(int(m.group(1)), int(m.group(2)))
                if got == ans_frac:
                    return 1.0, f"贝叶斯后验概率精确解出 {expected_str}"
                return 0.0, f"分数回答 {m.group(1)}/{m.group(2)}，正确答案应为 {expected_str}"
            except Exception:
                pass
        # Check decimal within tight tolerance
        val = _extract_last_number(cand)
        if val is not None and abs(val - float(ans_frac)) < 1e-4:
            return 0.85, f"数值精度接近 {expected_str}（未以最简分数给出）"
        return 0.0, f"未能得出正确后验概率 {expected_str}"

    return {
        "id": "iq_math_bayes",
        "dimension": "math_reasoning",
        "title": "非等概率贝叶斯精确分数推演",
        "difficulty": "hard",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": expected_str,
        "grader": grade,
    }


# ======================================================================
# Dimension 4: Code Static Dry-Run Execution Tracing (Python Semantics)
# ======================================================================


def _build_code_trace_state(rng: random.Random) -> dict[str, Any]:
    """Generate a Python stateful snippet testing list aliasing, slicing, XOR & modulo."""
    init = [rng.randint(2, 9) for _ in range(4)]
    k_xor = rng.randint(3, 13)
    mod_v = rng.choice([7, 11, 13])

    # Mirror exact computation in Python
    a = list(init)
    b = a  # aliasing trap!
    c = a[:]  # shallow copy!
    acc = 0
    for i in range(1, 5):
        v = (a[-1] + c[i - 1] * i) % mod_v
        b.append(v)
        if i % 2 == 1:
            acc = (acc ^ (v + k_xor)) + a[i]
        else:
            acc = acc - b.pop(0)
    expected_out = [acc, sum(a), len(c)]

    code_str = (
        f"a = {init}\n"
        f"b = a\n"
        f"c = a[:]\n"
        f"acc = 0\n"
        f"for i in range(1, 5):\n"
        f"    v = (a[-1] + c[i - 1] * i) % {mod_v}\n"
        f"    b.append(v)\n"
        f"    if i % 2 == 1:\n"
        f"        acc = (acc ^ (v + {k_xor})) + a[i]\n"
        f"    else:\n"
        f"        acc = acc - b.pop(0)\n"
        f"result = [acc, sum(a), len(c)]"
    )
    prompt = (
        "Trace the following Python 3 code step-by-step carefully without running any external interpreter. "
        "Pay close attention to list aliasing (`b = a` vs `c = a[:]`), `pop(0)`, and bitwise XOR (`^`).\n\n"
        f"```python\n{code_str}\n```\n\n"
        'What is the exact value of `result`? End with strict JSON: {"result": [<int>, <int>, <int>]}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if obj and isinstance(obj.get("result"), list) and len(obj["result"]) == 3:
            try:
                got = [int(x) for x in obj["result"]]
                if got == expected_out:
                    return 1.0, f"精确追踪 Python 引用别名与位运算状态机: {got}"
                hits = sum(1 for x, y in zip(got, expected_out) if x == y)
                return round((hits / 3.0) * 0.4, 3), f"输出 {got}，期望 {expected_out}（命中 {hits}/3 项）"
            except Exception:
                pass
        return 0.0, f"未能解析出正确的 3 元素结果，期望 {expected_out}"

    return {
        "id": "iq_code_trace_state",
        "dimension": "code_tracing",
        "title": "Python 引用别名与位运算状态机追踪",
        "difficulty": "extreme",
        "max_score": 16.0,
        "prompt": prompt,
        "expected": expected_out,
        "grader": grade,
    }


def _build_code_trace_recursion(rng: random.Random) -> dict[str, Any]:
    """Generate a tricky recursive function with mutable call counter & default-arg/branching."""
    n_start = rng.randint(5, 6)
    a_coef = rng.randint(2, 3)
    b_add = rng.randint(1, 4)

    calls = 0

    def f(n: int) -> int:
        nonlocal calls
        calls += 1
        if n <= 1:
            return n + b_add
        if n % 2 == 0:
            return f(n - 1) + a_coef * f(n // 2)
        return f(n - 1) - f(n - 2) + n

    val = f(n_start)
    expected = [val, calls]

    code_str = (
        f"calls = 0\n"
        f"def f(n):\n"
        f"    global calls\n"
        f"    calls += 1\n"
        f"    if n <= 1:\n"
        f"        return n + {b_add}\n"
        f"    if n % 2 == 0:\n"
        f"        return f(n - 1) + {a_coef} * f(n // 2)\n"
        f"    return f(n - 1) - f(n - 2) + n\n"
        f"ans = [f({n_start}), calls]"
    )
    prompt = (
        "Trace this recursive Python function carefully (no memoization is used).\n\n"
        f"```python\n{code_str}\n```\n\n"
        'Compute the exact `[f(n), calls]` pair. End with strict JSON: {"result": [<int>, <int>]}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if obj and isinstance(obj.get("result"), list) and len(obj["result"]) == 2:
            try:
                got = [int(x) for x in obj["result"]]
                if got == expected:
                    return 1.0, f"精确推演无记忆化递归树返回值与调用次数: {got}"
                hits = sum(1 for x, y in zip(got, expected) if x == y)
                return round((hits / 2.0) * 0.45, 3), f"输出 {got}，期望 {expected}"
            except Exception:
                pass
        return 0.0, f"未能解出精确递归值，期望 {expected}"

    return {
        "id": "iq_code_trace_rec",
        "dimension": "code_tracing",
        "title": "递归调用树与状态计数追踪",
        "difficulty": "extreme",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


# ======================================================================
# Dimension 5: Strict Multi-Constraint Instruction Following
# ======================================================================


def _build_instruction_constraints(rng: random.Random) -> dict[str, Any]:
    """Generate 6 simultaneous programmatically verifiable hard constraints."""
    acrostics = [
        ("SPARK", "e"),
        ("CLOUD", "i"),
        ("FROST", "a"),
        ("BLINK", "o"),
        ("CRISP", "u"),
    ]
    acrostic, forbidden = rng.choice(acrostics)
    exact_summary_words = rng.choice([7, 8, 9])

    prompt = (
        "Produce ONLY a single valid JSON object satisfying EVERY ONE of the following 6 strict constraints:\n"
        f'1. The JSON object must have EXACTLY three keys: "items", "checksum", and "summary".\n'
        f'2. "items" must be an array of EXACTLY {len(acrostic)} distinct lowercase English words (letters a-z only, each at least 3 letters long).\n'
        f'3. The first letters of the {len(acrostic)} words in "items", in order, must spell "{acrostic}" (case-insensitive).\n'
        f'4. NONE of the words in "items" may contain the letter "{forbidden}" anywhere.\n'
        f'5. "checksum" must be an integer equal to the EXACT sum of character lengths of all words in "items".\n'
        f'6. "summary" must be a plain English string containing EXACTLY {exact_summary_words} space-separated words.\n'
        "Return ONLY the JSON object, with no extra commentary."
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "无法解析出合法 JSON 对象"

        checks: list[tuple[str, bool]] = []
        keys_ok = set(obj.keys()) == {"items", "checksum", "summary"}
        checks.append(("精确3键", keys_ok))

        items = obj.get("items")
        words_ok = (
            isinstance(items, list)
            and len(items) == len(acrostic)
            and all(isinstance(w, str) and re.fullmatch(r"[a-z]{3,}", w) for w in items)
            and len(set(items)) == len(acrostic)
        )
        checks.append(("词表格式与去重", words_ok))

        acrostic_ok = False
        forbid_ok = False
        checksum_ok = False
        if isinstance(items, list) and len(items) == len(acrostic) and all(isinstance(w, str) and len(w) > 0 for w in items):
            initials = "".join(w[0].upper() for w in items)
            acrostic_ok = initials == acrostic
            forbid_ok = all(forbidden not in w.lower() for w in items)
            try:
                checksum_ok = int(obj.get("checksum", -1)) == sum(len(w) for w in items)
            except Exception:
                checksum_ok = False
        checks.append((f"藏头={acrostic}", acrostic_ok))
        checks.append((f"禁字='{forbidden}'", forbid_ok))
        checks.append(("精确字符校验和", checksum_ok))

        summary = obj.get("summary")
        summary_ok = isinstance(summary, str) and len(summary.strip().split()) == exact_summary_words
        checks.append((f"摘要恰{exact_summary_words}词", summary_ok))

        passed = sum(1 for _, ok in checks if ok)
        failed_names = [nm for nm, ok in checks if not ok]
        if passed == 6:
            return 1.0, "全部 6 项硬约束同时 100% 满足！"
        return round(passed / 6.0 * 0.85, 3), f"通过 {passed}/6 项；未满足: {', '.join(failed_names)}"

    return {
        "id": "iq_strict_constraints",
        "dimension": "instruction_following",
        "title": "六重并发硬约束精确遵循",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": {"acrostic": acrostic, "forbidden_letter": forbidden, "summary_words": exact_summary_words},
        "grader": grade,
    }


# ======================================================================
# Dimension 6: Multi-Hop Long-Context Needle-in-a-Haystack
# ======================================================================


def _build_long_context_multihop(rng: random.Random, mode: str) -> dict[str, Any]:
    """Generate a multi-hop 3-fact needle document to test reasoning + context truncation."""
    # Target filler lines: quick ~110 lines (~2.5k tok), standard ~320 lines (~7.5k tok), deep ~850 lines (~20k tok)
    n_lines = {"quick": 110, "standard": 320, "deep": 850}.get(mode, 320)

    proj_code = f"ORION-{rng.randint(100, 999)}"
    decoy_proj = f"ORION-{rng.randint(100, 999)}"
    while decoy_proj == proj_code:
        decoy_proj = f"ORION-{rng.randint(100, 999)}"

    engineer = rng.choice(["Dr. Lin Wei", "Dr. Hannah Park", "Dr. Marco Rossi", "Dr. Nadia Patel"])
    decoy_eng = rng.choice(["Dr. Owen Grant", "Dr. Sofia Morales", "Dr. Kenji Sato"])
    vault_id = f"VLT-{rng.randint(40, 89)}{rng.choice('ABCDEFGH')}"
    decoy_vault = f"VLT-{rng.randint(10, 39)}{rng.choice('JKLMNP')}"
    passphrase = f"{rng.choice(['QUARTZ', 'COBALT', 'NEBULA', 'SOLAR'])}-{rng.randint(1000, 9999)}-{rng.choice(['K7', 'M4', 'X9', 'R2'])}"
    decoy_pass = f"DECOY-{rng.randint(1000, 9999)}-Z0"

    # Place 3 hops at early (~12%), middle (~52%), and late (~88%) depths
    pos1 = max(5, int(n_lines * 0.12))
    pos2 = max(pos1 + 10, int(n_lines * 0.52))
    pos3 = max(pos2 + 10, int(n_lines * 0.88))

    decoy_pos1 = max(2, pos1 - 3)
    decoy_pos2 = min(n_lines - 3, pos2 + 5)

    topics = [
        "Thermal telemetry calibration completed on sector relay array with nominal drift within tolerance.",
        "Scheduled archive compaction rotated ledger blocks across regional storage clusters without incident.",
        "Optical fiber link audit confirmed redundant failover timing remained below 14 milliseconds.",
        "Cryogenic coolant valve inspection logged stable pressure gradients across auxiliary manifolds.",
        "Satellite ephemeris synchronization updated orbital covariance matrices for next transit window.",
    ]

    lines: list[str] = []
    for i in range(n_lines):
        if i == pos1:
            lines.append(f"[LOG-{i:04d}] ASSIGNMENT RECORD: Project {proj_code} is officially led by {engineer}.")
        elif i == decoy_pos1:
            lines.append(f"[LOG-{i:04d}] ASSIGNMENT RECORD: Project {decoy_proj} is officially led by {decoy_eng}.")
        elif i == pos2:
            lines.append(f"[LOG-{i:04d}] ACCESS REGISTRY: Lead engineer {engineer} holds exclusive authority over Vault {vault_id}.")
        elif i == decoy_pos2:
            lines.append(f"[LOG-{i:04d}] ACCESS REGISTRY: Lead engineer {decoy_eng} holds exclusive authority over Vault {decoy_vault}.")
        elif i == pos3:
            lines.append(f"[LOG-{i:04d}] SECURITY SEAL: The active override passphrase for Vault {vault_id} is {passphrase} (supersedes legacy keys).")
        elif i == pos3 - 4:
            lines.append(f"[LOG-{i:04d}] SECURITY SEAL: The active override passphrase for Vault {decoy_vault} is {decoy_pass}.")
        else:
            lines.append(f"[LOG-{i:04d}] {topics[i % len(topics)]} Batch-ID={(i*37 + 19) % 997:03d}.")

    doc = "\n".join(lines)
    approx_tokens = len(doc) // 4

    prompt = (
        "Read the following operational log archive carefully. "
        f"Trace the 3-step chain of records to find: (1) who leads Project {proj_code}, "
        "(2) which Vault that engineer controls, and (3) the active override passphrase for that Vault.\n\n"
        "--- ARCHIVE START ---\n"
        f"{doc}\n"
        "--- ARCHIVE END ---\n\n"
        f'Reply ONLY with strict JSON: {{"engineer": "<name>", "vault": "<vault_id>", "passphrase": "<passphrase>"}}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        txt = raw or ""
        eng_ok = engineer.lower() in (str(obj.get("engineer", "")).lower() if obj else txt.lower())
        vlt_ok = vault_id.lower() in (str(obj.get("vault", "")).lower() if obj else txt.lower())
        pwd_ok = passphrase.lower() in (str(obj.get("passphrase", "")).lower() if obj else txt.lower())
        hits = sum([eng_ok, vlt_ok, pwd_ok])
        if hits == 3:
            return 1.0, f"约 {approx_tokens:,} tokens 长文 3 跳精准溯源全部命中（未见上下文偷截断）"
        if hits == 0:
            return 0.0, f"3 跳均未命中（可能存在上下文截断或注意力严重衰退）；期望 {engineer} → {vault_id} → {passphrase}"
        return round(hits / 3.0 * 0.7, 3), f"命中 {hits}/3 跳 (engineer={eng_ok}, vault={vlt_ok}, passphrase={pwd_ok})"

    return {
        "id": "iq_long_multihop",
        "dimension": "long_context_needle",
        "title": f"长上下文三跳大海捞针 (~{approx_tokens:,} tok)",
        "difficulty": "hard",
        "max_score": 16.0,
        "prompt": prompt,
        "expected": {"engineer": engineer, "vault": vault_id, "passphrase": passphrase},
        "grader": grade,
    }


# ======================================================================
# IQ Suite Runner & Tier Classification
# ======================================================================


def _score_to_tier(score_100: float) -> tuple[str, str, int]:
    """Convert 0..100 normalized IQ score to Tier (S/A/B/C/D) & intuitive IQ index (~65..145)."""
    iq_index = int(round(65 + (max(0.0, min(100.0, score_100)) * 0.80)))
    if score_100 >= 88.0:
        return "S", "S 级 · 顶尖旗舰推理水平", iq_index
    if score_100 >= 74.0:
        return "A", "A 级 · 强主力/准旗舰水平", iq_index
    if score_100 >= 56.0:
        return "B", "B 级 · 轻量/中等模型水平", iq_index
    if score_100 >= 38.0:
        return "C", "C 级 · 入门/严重降智或低配水平", iq_index
    return "D", "D 级 · 极弱/严重异常水平", iq_index


def _check_claimed_tier_mismatch(model_name: str, score_100: float, tier: str) -> str | None:
    ml = model_name.lower()
    flagship_markers = (
        "fable",
        "opus",
        "gpt-6",
        "astra",
        "sol",
        "gpt-5",
        "o1",
        "o3",
        "o4-mini",
        "gemini-4-neon",
        "gemini-4-argon",
        "gemini-3.1-pro",
        "gemini-2.5-pro",
        "gemini-3",
        "claude-sonnet-5",
        "claude-sonnet-4",
        "claude-4",
        "deepseek-v4",
        "deepseek-r1",
    )
    is_flagship = any(m in ml for m in flagship_markers) and not any(
        x in ml for x in ("nano", "mini-2024", "haiku", "flash", "luna", "hydrogen", "lite")
    )
    if is_flagship and score_100 < 58.0:
        return (
            f"严重档位背离！请求模型 `{model_name}` 属于旗舰/高阶推理档位，"
            f"但动态反污染智商测评仅得 {score_100:.1f}/100 ({tier} 级)，"
            "远低于该档位正常下限，高度疑似被中转站降级替换、重度量化或偷砍推理预算！"
        )
    if is_flagship and score_100 < 72.0:
        return (
            f"智商偏低预警：请求模型 `{model_name}` 为高阶档位，但实测得分 {score_100:.1f}/100 ({tier} 级)，"
            "表现接近轻量模型区间，建议排查是否存在同系降级或暗降推理强度。"
        )
    return None


# ======================================================================
# Dimension 7: Executable Sandbox-Verified Code Bug Fixing
# ======================================================================

_SAFE_BUILTINS: dict[str, Any] = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "chr": chr,
    "dict": dict,
    "enumerate": enumerate,
    "Exception": Exception,
    "float": float,
    "IndexError": IndexError,
    "int": int,
    "isinstance": isinstance,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "ord": ord,
    "range": range,
    "reversed": reversed,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "ValueError": ValueError,
    "zip": zip,
}


def _extract_python_code(raw: str) -> str:
    s = re.sub(r"<think>.*?</think>", "", raw or "", flags=re.S | re.I).strip()
    blocks = re.findall(r"```(?:python|py)?\s*(.*?)```", s, flags=re.S | re.I)
    if blocks:
        # Pick block containing def solve_intervals if present
        for b in reversed(blocks):
            if "def solve_intervals" in b:
                return b.strip()
        return blocks[-1].strip()
    m = re.search(r"(def\s+solve_intervals\b.*)", s, flags=re.S)
    return m.group(1).strip() if m else s


def _ast_is_safe_pure_python(code: str) -> tuple[bool, str]:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return False, f"语法错误: {exc.msg}"

    forbidden_nodes = (ast.Import, ast.ImportFrom, ast.Global, ast.Delete)
    for node in ast.walk(tree):
        if isinstance(node, forbidden_nodes):
            return False, f"禁止语句: {type(node).__name__}"
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            return False, f"禁止访问双下划线属性: {node.attr}"
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            return False, f"禁止使用双下划线标识: {node.id}"
    return True, "ok"


def _build_code_bugfix(rng: random.Random) -> dict[str, Any]:
    """Generate a parameterized interval-merge bugfix challenge verified by 6 hidden tests."""
    max_gap = rng.randint(1, 3)
    min_len = rng.randint(4, 7)

    def ref_solve(intervals: list[list[int]], gap: int, mlen: int) -> list[list[int]]:
        valid = sorted(([int(a), int(b)] for a, b in intervals if a <= b), key=lambda x: (x[0], x[1]))
        if not valid:
            return []
        merged = [valid[0][:]]
        for s, e in valid[1:]:
            if s <= merged[-1][1] + gap:
                if e > merged[-1][1]:
                    merged[-1][1] = e
            else:
                merged.append([s, e])
        return [iv for iv in merged if (iv[1] - iv[0]) >= mlen]

    # 6 dynamically parameterized edge-case test vectors
    offset = rng.randint(-5, 5)
    test_cases = [
        ("空输入边界", []),
        ("乱序重叠+精确gap临界", [[10 + offset, 12 + offset], [2 + offset, 5 + offset], [5 + max_gap + offset, 9 + offset]]),
        ("忽略非法区间(start>end)", [[8, 3], [0, min_len], [min_len + max_gap + 1, min_len + max_gap + 2]]),
        ("嵌套包含区间(不可缩回end)", [[1, 12], [3, 6], [12 + max_gap, 14]]),
        ("多段链式合并达标", [[0, 2], [2 + max_gap, 4 + max_gap], [4 + 2 * max_gap, 10 + 2 * max_gap]]),
        ("全部短于min_len应过滤", [[1, 2], [20, 21]]),
    ]

    buggy_code = (
        "def solve_intervals(intervals, max_gap, min_len):\n"
        "    # BUGGY IMPLEMENTATION\n"
        "    merged = []\n"
        "    for s, e in intervals:\n"
        "        if not merged:\n"
        "            merged.append([s, e])\n"
        "        elif s < merged[-1][1] + max_gap:\n"
        "            merged[-1][1] = e\n"
        "        else:\n"
        "            merged.append([s, e])\n"
        "    return [iv for iv in merged if iv[1] - iv[0] > min_len]"
    )

    prompt = (
        "Fix ALL bugs in the following Python function `solve_intervals(intervals, max_gap, min_len)`.\n"
        "Exact specification:\n"
        "1. `intervals` is an UNSORTED list of `[start, end]` integer pairs. Ignore any invalid interval where `start > end`.\n"
        "2. Sort valid intervals by `(start, end)` and merge any two intervals whose gap is `<= max_gap` (i.e., `next_start <= cur_end + max_gap`).\n"
        "3. When merging nested intervals (e.g. `[1, 12]` and `[3, 6]`), keep the MAXIMUM end (`12`), never shrink it.\n"
        "4. Return only merged intervals whose length `(end - start)` is `>= min_len` (inclusive), sorted ascending.\n"
        "5. Do not use any imports. Return ONLY the corrected `def solve_intervals(...)` inside a ```python``` block.\n\n"
        f"```python\n{buggy_code}\n```"
    )

    def grade(raw: str) -> tuple[float, str]:
        code = _extract_python_code(raw)
        safe, msg = _ast_is_safe_pure_python(code)
        if not safe:
            return 0.0, f"安全检查/解析未通过: {msg}"

        ns: dict[str, Any] = {"__builtins__": _SAFE_BUILTINS}
        try:
            exec(compile(code, "<llm_bugfix>", "exec"), ns, ns)
        except Exception as exc:
            return 0.0, f"代码加载报错: {type(exc).__name__}: {exc}"

        fn = ns.get("solve_intervals")
        if not callable(fn):
            return 0.0, "未定义函数 `solve_intervals`"

        passed = 0
        failed_labels: list[str] = []

        def _eval_all() -> tuple[int, list[str]]:
            ok_cnt = 0
            fails: list[str] = []
            for label, inp in test_cases:
                exp = ref_solve(inp, max_gap, min_len)
                try:
                    got = fn([x[:] for x in inp], max_gap, min_len)
                    norm_got = [[int(a), int(b)] for a, b in got] if isinstance(got, list) else None
                    if norm_got == exp:
                        ok_cnt += 1
                    else:
                        fails.append(label)
                except Exception:
                    fails.append(f"{label}(异常)")
            return ok_cnt, fails

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_eval_all)
            try:
                passed, failed_labels = fut.result(timeout=1.5)
            except concurrent.futures.TimeoutError:
                return 0.0, "修复代码陷入死循环或超时 (>1.5s)"

        if passed == len(test_cases):
            return 1.0, f"沙箱 6/6 隐藏边界单元测试全部一次性通过！"
        return round((passed / len(test_cases)) * 0.75, 3), f"仅通过 {passed}/{len(test_cases)} 组单测；失败项: {', '.join(failed_labels)}"

    return {
        "id": "iq_code_bugfix",
        "dimension": "code_bugfix",
        "title": "沙箱单测验证：多边界算法 Bug 修复",
        "difficulty": "extreme",
        "max_score": 16.0,
        "prompt": prompt,
        "expected": f"Pass 6 hidden unit tests (max_gap={max_gap}, min_len={min_len})",
        "grader": grade,
    }


def _build_code_parser_challenge(rng: random.Random) -> dict[str, Any]:
    """Generate a dynamic custom-operator expression parser verified in AST sandbox."""
    k1 = rng.randint(2, 4)
    k2 = rng.randint(1, 3)

    # Custom binary op '@' defined as: a @ b = k1 * a - k2 * b
    # Precedence: '@' binds TIGHTER than '*' (highest binary precedence!), left-associative!
    def ref_eval(expr: str) -> int:
        tokens = re.findall(r"\d+|[+*@()]", expr)
        pos = 0

        def parse_add() -> int:
            nonlocal pos
            val = parse_mul()
            while pos < len(tokens) and tokens[pos] == "+":
                pos += 1
                val += parse_mul()
            return val

        def parse_mul() -> int:
            nonlocal pos
            val = parse_at()
            while pos < len(tokens) and tokens[pos] == "*":
                pos += 1
                val *= parse_at()
            return val

        def parse_at() -> int:
            nonlocal pos
            val = parse_atom()
            while pos < len(tokens) and tokens[pos] == "@":
                pos += 1
                rhs = parse_atom()
                val = k1 * val - k2 * rhs
            return val

        def parse_atom() -> int:
            nonlocal pos
            tok = tokens[pos]
            if tok == "(":
                pos += 1
                v = parse_add()
                pos += 1  # consume ')'
                return v
            pos += 1
            return int(tok)

        return parse_add()

    a, b, c, d = rng.randint(2, 9), rng.randint(2, 9), rng.randint(2, 8), rng.randint(1, 7)
    cases = [
        ("基础自定义运算", f"{a} @ {b}"),
        ("左结合链式@", f"{a + 3} @ {b} @ {c}"),
        ("@高于*优先级", f"{c} * {a} @ {b} + {d}"),
        ("括号改写优先级", f"({c} + {a}) @ ({b} * {d})"),
        ("深层嵌套括号", f"(({a} + {b}) * ({c} @ {d})) + {a} @ {c}"),
        ("多位数无空格", f"{a + 10}@{b + 1}+{c}*({d + 2}@{a})"),
    ]

    prompt = (
        "Write a pure Python 3 function `def eval_custom(expr: str) -> int:` that evaluates integer arithmetic expressions.\n"
        "Exact grammar & rules:\n"
        "- Tokens: non-negative multi-digit integers, optional whitespace, parentheses `(` `)`, and 3 binary operators `+`, `*`, `@`.\n"
        f"- The custom operator `@` is defined as: `x @ y = {k1} * x - {k2} * y`.\n"
        "- Operator precedence from HIGHEST to LOWEST: parentheses `()`, then `@`, then `*`, then `+`.\n"
        "- All binary operators (`@`, `*`, `+`) are LEFT-associative (e.g., `a @ b @ c` means `(a @ b) @ c`).\n"
        "- Do NOT use any imports, and do NOT call `eval`, `exec`, or `compile`.\n"
        "Return ONLY `def eval_custom(expr): ...` inside a ```python``` code block."
    )

    def grade(raw: str) -> tuple[float, str]:
        s = re.sub(r"<think>.*?</think>", "", raw or "", flags=re.S | re.I).strip()
        blocks = re.findall(r"```(?:python|py)?\s*(.*?)```", s, flags=re.S | re.I)
        code = ""
        if blocks:
            for blk in reversed(blocks):
                if "def eval_custom" in blk:
                    code = blk.strip()
                    break
            if not code:
                code = blocks[-1].strip()
        else:
            m = re.search(r"(def\s+eval_custom\b.*)", s, flags=re.S)
            code = m.group(1).strip() if m else s

        safe, msg = _ast_is_safe_pure_python(code)
        if not safe:
            return 0.0, f"安全检查/解析未通过: {msg}"

        ns: dict[str, Any] = {"__builtins__": _SAFE_BUILTINS}
        try:
            exec(compile(code, "<llm_parser>", "exec"), ns, ns)
        except Exception as exc:
            return 0.0, f"代码加载报错: {type(exc).__name__}: {exc}"

        fn = ns.get("eval_custom")
        if not callable(fn):
            return 0.0, "未定义函数 `eval_custom`"

        def _eval_cases() -> tuple[int, list[str]]:
            ok_cnt = 0
            fails: list[str] = []
            for lbl, expr in cases:
                exp = ref_eval(expr)
                try:
                    got = int(fn(expr))
                    if got == exp:
                        ok_cnt += 1
                    else:
                        fails.append(f"{lbl}(得{got}/期{exp})")
                except Exception:
                    fails.append(f"{lbl}(异常)")
            return ok_cnt, fails

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_eval_cases)
            try:
                passed, fails = fut.result(timeout=1.5)
            except concurrent.futures.TimeoutError:
                return 0.0, "解析器陷入死循环或超时 (>1.5s)"

        if passed == len(cases):
            return 1.0, f"自定义优先级递归下降解析器 6/6 隐藏单测全通 (@={k1}x-{k2}y)！"
        return round((passed / len(cases)) * 0.75, 3), f"通过 {passed}/6 组单测；失败: {', '.join(fails[:3])}"

    return {
        "id": "iq_code_parser",
        "dimension": "code_bugfix",
        "title": "沙箱单测验证：自定义优先级表达式解析器",
        "difficulty": "extreme",
        "max_score": 16.0,
        "prompt": prompt,
        "expected": f"Pass 6 hidden parser tests (x @ y = {k1}*x - {k2}*y, precedence: @ > * > +)",
        "grader": grade,
    }


# ======================================================================
# Dimension 8: 2D Spatial Grid + Obstacles + Portal State Simulation
# ======================================================================


def _build_spatial_grid_sim(rng: random.Random) -> dict[str, Any]:
    """Generate a deterministic 6x6 spatial navigation simulation with walls & portal."""
    size = 6
    dirs = ["N", "E", "S", "W"]
    # Coordinate convention explicitly stated: x=column (0..5 left->right), y=row (0..5 top->bottom)
    delta_map = {"N": (0, -1), "E": (1, 0), "S": (0, 1), "W": (-1, 0)}

    all_cells = [(x, y) for x in range(size) for y in range(size)]
    picked = rng.sample(all_cells, 7)
    start_x, start_y = picked[0]
    obstacles = set(picked[1:5])
    portal_in = picked[5]
    portal_out = picked[6]
    start_dir = rng.choice(dirs)

    cmds = [rng.choice(["F", "F", "F2", "L", "R"]) for _ in range(9)]
    # Ensure at least 4 movement commands so it's genuinely challenging
    cmds[0] = "F2"
    cmds[3] = "F"
    cmds[6] = "F2"

    # Exact deterministic simulation
    x, y, d_idx = start_x, start_y, dirs.index(start_dir)
    for cmd in cmds:
        if cmd == "L":
            d_idx = (d_idx - 1) % 4
        elif cmd == "R":
            d_idx = (d_idx + 1) % 4
        else:
            steps = 2 if cmd == "F2" else 1
            for _ in range(steps):
                dx, dy = delta_map[dirs[d_idx]]
                nx, ny = x + dx, y + dy
                if not (0 <= nx < size and 0 <= ny < size) or (nx, ny) in obstacles:
                    # Blocked by boundary or obstacle: stay in place and turn 90° clockwise
                    d_idx = (d_idx + 1) % 4
                else:
                    x, y = nx, ny
                    if (x, y) == portal_in:
                        x, y = portal_out

    expected = {"x": x, "y": y, "facing": dirs[d_idx]}
    obs_list = sorted([list(p) for p in obstacles])

    prompt = (
        f"A rover operates on a {size}x{size} grid where x goes from 0 (west) to {size-1} (east), "
        f"and y goes from 0 (north/top) to {size-1} (south/bottom).\n"
        f"- Directions: N=(0,-1), E=(+1,0), S=(0,+1), W=(-1,0).\n"
        f"- Start state: x={start_x}, y={start_y}, facing={start_dir}.\n"
        f"- Blocked obstacle cells: {obs_list}.\n"
        f"- One-way teleport portal: stepping onto {list(portal_in)} immediately teleports the rover to {list(portal_out)} (keeping the same facing).\n"
        f"- Commands:\n"
        f"  * L: turn 90° counter-clockwise (N→W→S→E→N).\n"
        f"  * R: turn 90° clockwise (N→E→S→W→N).\n"
        f"  * F: attempt to step 1 cell forward. If the target cell is out of bounds or an obstacle, DO NOT move; instead stay in place and turn 90° clockwise.\n"
        f"  * F2: execute F twice in sequence (two separate 1-cell steps).\n\n"
        f"Execute this exact command sequence in order: {cmds}\n"
        'End your response with strict JSON: {"x": <int>, "y": <int>, "facing": "N|E|S|W"}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析的 JSON 坐标状态"
        try:
            gx = int(obj.get("x", -99))
            gy = int(obj.get("y", -99))
            gf = str(obj.get("facing", "")).strip().upper()
        except Exception:
            return 0.0, "坐标字段格式非法"
        pos_ok = (gx == expected["x"] and gy == expected["y"])
        dir_ok = (gf == expected["facing"])
        if pos_ok and dir_ok:
            return 1.0, f"9 步二维网格碰撞+传送门状态机推演 100% 精确 ({gx},{gy},{gf})"
        if pos_ok:
            return 0.65, f"坐标 ({gx},{gy}) 正确但朝向错误（答 {gf}，期望 {expected['facing']}）"
        return 0.0, f"推演结果 ({gx},{gy},{gf})，正确答案应为 ({expected['x']},{expected['y']},{expected['facing']})"

    return {
        "id": "iq_spatial_grid",
        "dimension": "spatial_sim",
        "title": "6×6 障碍+传送门二维空间状态模拟",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


def _int_to_cn_financial(n: int) -> str:
    """Convert 11..99 to Chinese financial uppercase numerals (e.g. 35 -> 叁拾伍)."""
    digits = "零壹贰叁肆伍陆柒捌玖"
    tens, ones = divmod(n, 10)
    if tens == 1:
        return "拾" + (digits[ones] if ones else "")
    return digits[tens] + "拾" + (digits[ones] if ones else "")


def _build_bilingual_nuance(rng: random.Random) -> dict[str, Any]:
    """Cross-lingual Chinese financial numerals + double-negation rule reasoning."""
    threshold = rng.choice([28, 34, 42, 56, 63, 74])
    thresh_cn = _int_to_cn_financial(threshold)
    min_years = rng.randint(3, 6)
    min_years_cn = "零壹贰叁肆伍陆柒捌玖"[min_years]

    candidates_pool = [
        ("LIN", "林工"),
        ("CHEN", "陈工"),
        ("ZHOU", "周工"),
        ("XU", "许工"),
        ("HAN", "韩工"),
    ]
    picked = rng.sample(candidates_pool, 4)

    # Generate 4 profiles ensuring at least 1 passes and at least 1 fails via tricky double-negation
    profiles = []
    # Profile 0: guaranteed PASS (score >= threshold, years >= min_years, NO violation)
    profiles.append((picked[0][0], picked[0][1], threshold + rng.randint(2, 12), min_years + rng.randint(0, 3), False, False))
    # Profile 1: PASS via special waiver (score < threshold, NOT lacking award == has award, years >= min_years, no violation)
    profiles.append((picked[1][0], picked[1][1], threshold - rng.randint(3, 8), min_years + 1, True, False))
    # Profile 2: FAIL because has violation despite high score
    profiles.append((picked[2][0], picked[2][1], threshold + rng.randint(10, 20), min_years + 2, True, True))
    # Profile 3: FAIL because years < min_years (even though score >= threshold)
    profiles.append((picked[3][0], picked[3][1], threshold + rng.randint(1, 9), min_years - 1, False, False))
    rng.shuffle(profiles)

    # Exact programmatic rule:
    # Qualifies iff: (not violation) AND (years >= min_years) AND (score >= threshold OR has_award)
    qualified_ids = sorted(
        code
        for (code, _nm, sc, yrs, has_award, violation) in profiles
        if (not violation) and (yrs >= min_years) and (sc >= threshold or has_award)
    )

    desc_lines = []
    for code, nm, sc, yrs, has_award, violation in profiles:
        sc_cn = _int_to_cn_financial(sc)
        award_txt = "并非未曾获得过年度技术奖" if has_award else "从未获得过年度技术奖"
        viol_txt = "近两年并非没有安全违规记录" if violation else "近两年未曾出现任何安全违规记录"
        desc_lines.append(
            f"- 编号 `{code}` ({nm})：考核分为「{sc_cn}」分，工龄 {yrs} 年，{award_txt}，且{viol_txt}。"
        )

    prompt = (
        "请仔细阅读以下包含中文财务大写数字与双重否定逻辑的评审规则，并筛选所有符合晋升资格的候选人编号：\n"
        f"规则 1：除非近两年没有任何安全违规记录，否则一律不得通过。\n"
        f"规则 2：工龄不得少于「{min_years_cn}」年（含）。\n"
        f"规则 3：考核分不得低于「{thresh_cn}」分（含）；但若申请人并非没有获得过年度技术奖，则可豁免本条分数门槛。\n\n"
        "候选人档案：\n"
        + "\n".join(desc_lines)
        + '\n\n请只返回严格 JSON（`qualified` 为按字母升序排列的英文编号数组，`threshold_num` 为规则3门槛的阿拉伯整数）：'
        '{"qualified": ["..."], "threshold_num": <int>}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析的 JSON 结果"
        got_q = obj.get("qualified")
        q_ok = (
            isinstance(got_q, list)
            and sorted(str(x).strip().upper() for x in got_q) == qualified_ids
        )
        try:
            t_ok = int(obj.get("threshold_num", -1)) == threshold
        except Exception:
            t_ok = False
        if q_ok and t_ok:
            return 1.0, f"中文大写数字 ({thresh_cn}={threshold}) 与双重否定规则精准解析，命中 {qualified_ids}"
        if q_ok:
            return 0.75, f"候选人列表 {qualified_ids} 正确，但大写数字转换错误"
        if t_ok:
            return 0.25, f"大写数字 {threshold} 正确，但双重否定筛选错误（答 {got_q}，期 {qualified_ids}）"
        return 0.0, f"中文大写数字与双重否定筛选均错误（期望 {qualified_ids}, {threshold}）"

    return {
        "id": "iq_bilingual_nuance",
        "dimension": "deductive_logic",
        "title": "中英双语：中文大写数字与双重否定逻辑精读",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": {"qualified": qualified_ids, "threshold_num": threshold},
        "grader": grade,
    }


def _build_sqlite_sql_challenge(rng: random.Random) -> dict[str, Any]:
    """Executable read-only SQLite :memory: SQL query challenge with LEFT JOIN + NULL handling."""
    names = rng.sample(["Alice", "Benoit", "Chen", "Diana", "Elena", "Farid"], 5)
    tiers = ["VIP", "VIP", "VIP", "STD", "STD"]
    rng.shuffle(tiers)
    customers = [(i + 1, names[i], tiers[i]) for i in range(5)]

    orders: list[tuple[int, int, int, str]] = []
    oid = 101
    # Customer 1..4 get randomized orders; Customer 5 intentionally has 0 paid orders!
    for cid in range(1, 5):
        for _ in range(rng.randint(2, 3)):
            amt = rng.choice([80, 120, 150, 200, 250, 300])
            st = rng.choice(["paid", "paid", "paid", "cancelled"])
            orders.append((oid, cid, amt, st))
            oid += 1
    orders.append((oid, 5, 190, "cancelled"))

    paid_ids = [o[0] for o in orders if o[3] == "paid"]
    refund_picks = rng.sample(paid_ids, min(3, len(paid_ids)))
    refunds = [(rid, rng.choice([20, 35, 50])) for rid in refund_picks]

    def _seed_db() -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, tier TEXT)")
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, amount INTEGER, status TEXT)")
        conn.execute("CREATE TABLE refunds (order_id INTEGER, refund_amt INTEGER)")
        conn.executemany("INSERT INTO customers VALUES (?, ?, ?)", customers)
        conn.executemany("INSERT INTO orders VALUES (?, ?, ?, ?)", orders)
        conn.executemany("INSERT INTO refunds VALUES (?, ?)", refunds)
        return conn

    ref_sql = (
        "SELECT c.name, "
        "COALESCE(SUM(CASE WHEN o.status = 'paid' THEN o.amount - COALESCE(r.refund_amt, 0) ELSE 0 END), 0) AS net_spend "
        "FROM customers c "
        "LEFT JOIN orders o ON c.id = o.customer_id "
        "LEFT JOIN refunds r ON o.id = r.order_id "
        "GROUP BY c.id, c.name "
        "ORDER BY net_spend DESC, c.name ASC"
    )
    conn_ref = _seed_db()
    expected_rows = [(str(r[0]), int(r[1])) for r in conn_ref.execute(ref_sql).fetchall()]
    conn_ref.close()

    prompt = (
        "Write a single standard SQLite SELECT query for the following schema:\n"
        "  customers(id INTEGER, name TEXT, tier TEXT)\n"
        "  orders(id INTEGER, customer_id INTEGER, amount INTEGER, status TEXT) -- status is 'paid' or 'cancelled'\n"
        "  refunds(order_id INTEGER, refund_amt INTEGER) -- at most one refund row per order, may be absent\n\n"
        "Requirements:\n"
        "1. Return ALL customers (including customers with zero paid orders, whose net_spend MUST be 0).\n"
        "2. Columns: (name, net_spend) where net_spend = SUM of (amount - refund_amt) across ONLY 'paid' orders "
        "(treat missing refund_amt as 0; completely ignore 'cancelled' orders).\n"
        "3. Sort by net_spend DESC, then name ASC.\n\n"
        'Return ONLY strict JSON: {"sql": "SELECT ..."}'
    )

    def _extract_sql(raw: str) -> str:
        obj = _extract_json_obj(raw)
        if isinstance(obj, dict) and isinstance(obj.get("sql"), str) and obj["sql"].strip():
            return obj["sql"].strip()
        s = re.sub(r"<think>.*?</think>", "", raw or "", flags=re.S | re.I)
        m = re.findall(r"```(?:sql)?\s*(SELECT.*?)```", s, flags=re.S | re.I)
        if m:
            return m[-1].strip()
        m2 = re.search(r"(SELECT\b.*)", s, flags=re.S | re.I)
        return m2.group(1).strip() if m2 else ""

    def grade(raw: str) -> tuple[float, str]:
        sql = _extract_sql(raw).rstrip(";").strip()
        if not sql or not sql.upper().startswith(("SELECT", "WITH")):
            return 0.0, "未提取到合法的 SELECT 查询语句"
        if ";" in sql:
            return 0.0, "安全拦截：禁止多语句分号拼接"

        conn = _seed_db()
        try:
            allowed_actions = {
                sqlite3.SQLITE_SELECT,
                sqlite3.SQLITE_READ,
                sqlite3.SQLITE_FUNCTION,
                getattr(sqlite3, "SQLITE_RECURSIVE", 33),
            }

            def _authorizer(action: int, arg1: Any, arg2: Any, db: Any, trig: Any) -> int:
                return sqlite3.SQLITE_OK if action in allowed_actions else sqlite3.SQLITE_DENY

            conn.set_authorizer(_authorizer)
            got = conn.execute(sql).fetchmany(50)
            norm_got = []
            for row in got:
                if len(row) != 2:
                    return 0.0, f"返回列数为 {len(row)}，期望恰好 2 列 (name, net_spend)"
                norm_got.append((str(row[0]), int(round(float(row[1])) if row[1] is not None else -999999)))
            if norm_got == expected_rows:
                return 1.0, f"内存 SQLite 只读沙箱实测 100% 匹配全部 {len(expected_rows)} 行（含 0 订单与 NULL 退款边界）"
            if sorted(norm_got) == sorted(expected_rows):
                return 0.7, "聚合数值完全正确，但排序未严格按 net_spend DESC, name ASC"
            return 0.0, f"SQL 结果不匹配（实际: {norm_got[:4]}，期望: {expected_rows[:4]}）"
        except Exception as exc:
            return 0.0, f"SQL 执行或权限报错: {type(exc).__name__}: {str(exc)[:100]}"
        finally:
            conn.close()

    return {
        "id": "iq_sqlite_sql",
        "dimension": "engineering_sql",
        "title": "可执行 SQLite 内存沙箱：多表 LEFT JOIN 与 NULL 聚合",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": expected_rows,
        "grader": grade,
    }


def _build_unified_diff_challenge(rng: random.Random) -> dict[str, Any]:
    """Minimal surgical line-patch challenge verified by AST sandbox + untouched-code check."""
    bonus = rng.randint(2, 6)
    cap = rng.randint(40, 80)
    src_lines = [
        "def clamp_window(vals, lo, hi):",
        "    out = []",
        "    for v in vals:",
        "        out.append(max(lo, min(hi, v)))",
        "    return out",
        "",
        "def rolling_capped_sum(nums, k):",
        f"    # Must return list of sums of every contiguous window of length k,",
        f"    # adding +{bonus} only when the window contains a negative number,",
        f"    # and capping each result at {cap}. Return [] if k <= 0 or k > len(nums).",
        "    if k < 0 or k >= len(nums):",
        "        return []",
        "    res = []",
        "    for i in range(len(nums) - k):",
        "        win = nums[i : i + k]",
        "        s = sum(win)",
        "        if any(x <= 0 for x in win):",
        f"            s += {bonus}",
        f"        res.append(min({cap}, s))",
        "    return res",
    ]
    numbered = "\n".join(f"{i+1:02d}| {line}" for i, line in enumerate(src_lines))

    def ref_fn(nums: list[int], k: int) -> list[int]:
        if k <= 0 or k > len(nums):
            return []
        res = []
        for i in range(len(nums) - k + 1):
            win = nums[i : i + k]
            s = sum(win)
            if any(x < 0 for x in win):
                s += bonus
            res.append(min(cap, s))
        return res

    test_cases = [
        ([10, 20, 30], 3),
        ([5, 0, 5, -2, 10], 2),
        ([cap, 10, -1], 2),
        ([1, 2, 3], 0),
        ([4, 5], 5),
    ]

    prompt = (
        "Inspect this numbered Python file. `clamp_window` is already correct and MUST NOT be modified. "
        "`rolling_capped_sum` has 3 subtle boundary bugs relative to its comment spec:\n\n"
        f"```python\n{numbered}\n```\n\n"
        "Return a MINIMAL surgical line-patch JSON editing ONLY the buggy lines (1-indexed inclusive `start_line`..`end_line`). "
        "Do NOT touch lines 1-6, and do NOT use `...` placeholders.\n"
        'Reply ONLY with strict JSON: {"edits": [{"start_line": <int>, "end_line": <int>, "replacement": ["    ...", ...]}]}'
    )

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict) or not isinstance(obj.get("edits"), list) or not obj["edits"]:
            return 0.0, "未输出合法的 JSON edits 补丁列表"
        edits = obj["edits"]
        patched = list(src_lines)
        total_touched = 0
        try:
            parsed_edits = []
            for e in edits:
                st = int(e["start_line"])
                en = int(e["end_line"])
                rep = e["replacement"]
                if not isinstance(rep, list) or st < 1 or en < st or en > len(src_lines):
                    return 0.0, f"补丁行号越界: {st}..{en}"
                if st <= 6:
                    return 0.0, "违反最小改动约束：修改了禁止触碰的 clamp_window (1-6行)"
                if any("..." in str(ln) for ln in rep):
                    return 0.0, "补丁包含懒惰省略号 `...`"
                total_touched += (en - st + 1)
                parsed_edits.append((st, en, [str(ln) for ln in rep]))
            # Apply bottom-up so indices remain stable
            for st, en, rep in sorted(parsed_edits, key=lambda x: x[0], reverse=True):
                patched[st - 1 : en] = rep
        except Exception as exc:
            return 0.0, f"应用行级补丁失败: {exc}"

        code = "\n".join(patched)
        safe, reason = _ast_is_safe_pure_python(code)
        if not safe:
            return 0.0, f"安全沙箱拦截: {reason}"

        ns: dict[str, Any] = {}
        try:
            exec(compile(code, "<iq_patch>", "exec"), {"__builtins__": _SAFE_BUILTINS}, ns)
            fn = ns.get("rolling_capped_sum")
            if not callable(fn):
                return 0.0, "补丁后找不到 rolling_capped_sum 函数"
            passed_cnt = 0
            for nums, k in test_cases:
                if fn(list(nums), k) == ref_fn(nums, k):
                    passed_cnt += 1
        except Exception as exc:
            return 0.0, f"补丁代码执行报错: {type(exc).__name__}: {exc}"

        if passed_cnt == len(test_cases):
            if total_touched <= 9:
                return 1.0, f"精准外科手术式行级补丁（仅改 {total_touched} 行），5/5 隐藏单测全过！"
            return 0.85, f"5/5 单测全过，但改动行数较多 ({total_touched} 行)"
        return round((passed_cnt / len(test_cases)) * 0.6, 2), f"补丁仅通过 {passed_cnt}/{len(test_cases)} 组隐藏单测"

    return {
        "id": "iq_surgical_patch",
        "dimension": "code_bugfix",
        "title": "精准外科手术式代码补丁（行号 Diff + 5 组单测）",
        "difficulty": "hard",
        "max_score": 14.0,
        "prompt": prompt,
        "expected": "minimal line patch passing 5/5 hidden boundary tests",
        "grader": grade,
    }


def _build_rag_faithfulness_challenge(rng: random.Random) -> dict[str, Any]:
    """Private counter-intuitive API spec testing RAG faithfulness & honest NOT_SPECIFIED abstention."""
    ver = f"{rng.randint(3, 8)}.{rng.randint(1, 9)}"
    ok_code = rng.choice([209, 212, 218, 224])
    mean_200 = rng.choice(["SHADOW_THROTTLED", "DRY_RUN_ONLY", "SOFT_REJECTED"])
    hdr_name = rng.choice(["X-Nova-Ticket", "X-Vault-Seal", "X-Pulse-Token"])
    unit_mult = rng.choice([10, 20])  # e.g. tenths of a second -> value 35 means 3.5s
    sample_val = rng.choice([30, 40, 50, 60])
    expected_sec = round(sample_val / unit_mult, 2)
    unit_desc = "tenths of a second (1/10 s)" if unit_mult == 10 else "twentieths of a second (1/20 s)"

    spec_doc = (
        f"=== INTERNAL SPEC: NovaLedger Private Gateway v{ver} ===\n"
        f"Section 1 (Status Semantics): Contrary to standard REST conventions, NovaLedger v{ver} "
        f"returns HTTP {ok_code} to confirm a committed write transaction. "
        f"A response with HTTP 200 MUST be treated by all clients as `{mean_200}` and never as committed.\n"
        f"Section 2 (Authentication): Do NOT send `Authorization: Bearer`. Requests MUST pass the credential "
        f"exclusively in header `{hdr_name}` with no prefix.\n"
        f"Section 3 (Legacy Timeout Field): Despite its misleading legacy name, the integer field `window_ms` "
        f"is measured in {unit_desc}, NOT milliseconds.\n"
        "Section 4 (Retries): Clients may retry idempotent calls up to 3 times on HTTP 503. "
        "(Note: No jitter backoff formula or `max_retry_jitter_sec` parameter is defined anywhere in this specification.)\n"
    )

    prompt = (
        "Answer strictly based ONLY on the private internal specification below. "
        "Do NOT rely on outside REST conventions. If a requested detail is NOT specified in the document, "
        'you MUST return the exact string "NOT_SPECIFIED".\n\n'
        f"{spec_doc}\n"
        "Return ONLY strict JSON:\n"
        "{\n"
        '  "committed_http_code": <int>,\n'
        '  "http_200_meaning": "<exact status tag>",\n'
        f'  "window_{sample_val}_in_seconds": <number>,\n'
        '  "auth_header_name": "<header>",\n'
        '  "max_retry_jitter_sec": "<value or NOT_SPECIFIED>"\n'
        "}"
    )

    sec_key = f"window_{sample_val}_in_seconds"
    expected = {
        "committed_http_code": ok_code,
        "http_200_meaning": mean_200,
        sec_key: expected_sec,
        "auth_header_name": hdr_name,
        "max_retry_jitter_sec": "NOT_SPECIFIED",
    }

    def grade(raw: str) -> tuple[float, str]:
        obj = _extract_json_obj(raw)
        if not isinstance(obj, dict):
            return 0.0, "未输出可解析的 JSON"
        hits = 0
        notes = []
        try:
            if int(obj.get("committed_http_code", -1)) == ok_code:
                hits += 1
            else:
                notes.append("状态码未遵循反常识文档")
        except Exception:
            notes.append("状态码格式错")
        if str(obj.get("http_200_meaning", "")).strip().upper() == mean_200:
            hits += 1
        else:
            notes.append("HTTP200语义错")
        try:
            if abs(float(obj.get(sec_key, -1)) - expected_sec) < 0.02:
                hits += 1
            else:
                notes.append("window_ms反常识单位换算错")
        except Exception:
            notes.append("秒数格式错")
        if str(obj.get("auth_header_name", "")).strip().lower() == hdr_name.lower():
            hits += 1
        else:
            notes.append("鉴权头错")
        j_val = str(obj.get("max_retry_jitter_sec", "")).strip().upper()
        if j_val == "NOT_SPECIFIED":
            hits += 1
        else:
            notes.append(f"幻觉编造未定义参数({j_val[:20]})")
        if hits == 5:
            return 1.0, "5/5 私有反常识规格忠实遵循 + 零幻觉诚实拒答通过！"
        return round(hits / 5.0, 2), f"RAG 忠实度 {hits}/5 ({'；'.join(notes)})"

    return {
        "id": "iq_rag_faithfulness",
        "dimension": "rag_faithfulness",
        "title": "私有反常识文档忠实度与零幻觉拒答",
        "difficulty": "medium",
        "max_score": 12.0,
        "prompt": prompt,
        "expected": expected,
        "grader": grade,
    }


def run_iq_suite(
    client: RelayClient,
    config: AuditConfig,
    emit: ProgressCb | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[list[EvidenceItem], IQSummary]:
    """Execute the 10-dimension doubled dynamic anti-contamination IQ suite (31 generator bank)."""
    from .probes_iq_extended import get_extended_iq_builders

    seed = config.iq_seed if config.iq_seed is not None else random.randint(100000, 999999)
    rng = random.Random(seed)
    ext = get_extended_iq_builders()

    def notify(step: str, msg: str) -> None:
        if emit:
            emit(step, msg)

    # Assemble DOUBLED question battery (all 10 dimensions covered even in quick mode!)
    # quick: 16 base (+1 long_context = 17) | standard: 30 (+1 long_context = 31) | deep: 34
    specs: list[dict[str, Any]] = [
        _build_anti_bias_crystal(rng),
        ext["simpson"](rng),
        _build_logic_grid(rng),
        ext["sat5"](rng),
        _build_bilingual_nuance(rng),
        _build_math_crt(rng),
        ext["comb_ie"](rng),
        ext["dijkstra"](rng),
        _build_code_trace_state(rng),
        ext["closure"](rng),
        _build_code_bugfix(rng),
        _build_sqlite_sql_challenge(rng),
        _build_spatial_grid_sim(rng),
        ext["die3d"](rng),
        _build_instruction_constraints(rng),
        _build_rag_faithfulness_challenge(rng),
    ]
    if config.mode in ("standard", "deep"):
        specs.extend([
            _build_anti_bias_crossing(rng),
            _build_anti_bias_pricing(rng),
            ext["harmonic"](rng),
            _build_knights_knaves(rng),
            ext["dag"](rng),
            ext["tiered_cn"](rng),
            _build_math_bayes(rng),
            ext["modpow"](rng),
            _build_code_trace_recursion(rng),
            _build_code_parser_challenge(rng),
            _build_unified_diff_challenge(rng),
            ext["dp_sandbox"](rng),
            ext["sql_having"](rng),
            ext["instr_xform"](rng),
            ext["rag_amend"](rng),
        ])
    if config.mode == "deep":
        # Extra fresh-seed high-difficulty reinforcement variants (total 34+ questions!)
        extra_hard = [
            ("iq_logic_sat5_v2", ext["sat5"](rng)),
            ("iq_spatial_die3d_v2", ext["die3d"](rng)),
            ("iq_math_modpow_v2", ext["modpow"](rng)),
        ]
        for new_id, item in extra_hard:
            item["id"] = new_id
            item["title"] = item["title"] + " (加试题)"
            specs.append(item)
    if config.run_long_context:
        specs.append(_build_long_context_multihop(rng, config.mode))

    total_q = len(specs)
    results_ordered: list[IQQuestionResult | None] = [None] * total_q
    completed_cnt = 0
    max_workers = max(1, min(4, int(config.max_concurrency or 4)))

    def _run_one_iq(idx_0: int, q: dict[str, Any]) -> tuple[int, IQQuestionResult | None]:
        if cancel_check and cancel_check():
            return idx_0, None
        max_tok = 2048 if q["difficulty"] in ("hard", "extreme") else 1024
        res = client.chat(
            messages=[{"role": "user", "content": q["prompt"]}],
            max_tokens=max_tok,
            temperature=0.0,
        )
        if res.ok and res.text:
            frac, notes = q["grader"](res.text)
            earned = round(q["max_score"] * frac, 2)
            passed = frac >= 0.85
            actual_str = res.text.strip()
        else:
            earned = 0.0
            passed = False
            actual_str = f"[ERROR HTTP {res.status_code}] {res.error}"
            notes = f"请求失败或返回空内容: {res.error[:120]}"

        qr = IQQuestionResult(
            id=q["id"],
            dimension=q["dimension"],
            dimension_label=_DIMENSION_LABELS[q["dimension"]],
            title=q["title"],
            difficulty=q["difficulty"],
            max_score=q["max_score"],
            score=earned,
            passed=passed,
            latency_ms=round(res.latency_ms, 1),
            reasoning_tokens=res.reasoning_tokens,
            output_tokens=res.output_tokens,
            prompt_preview=q["prompt"][:320] + ("..." if len(q["prompt"]) > 320 else ""),
            expected=q["expected"],
            actual=actual_str[:600],
            grading_notes=notes,
        )
        return idx_0, qr

    notify("iq_start", f"启动 10 维扩容题库智商测评（共 {total_q} 道动态防背题新题，{max_workers} 路并发加速）...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(_run_one_iq, i, q) for i, q in enumerate(specs)]
        for fut in concurrent.futures.as_completed(futs):
            idx_0, qr = fut.result()
            completed_cnt += 1
            if qr is not None:
                results_ordered[idx_0] = qr
                notify(
                    "iq_question",
                    f"智商测评进度 ({completed_cnt}/{total_q})：{qr.dimension_label} — {qr.title} [{'通过' if qr.passed else '未过'}]",
                )

    results: list[IQQuestionResult] = [r for r in results_ordered if r is not None]
    dim_buckets: dict[str, dict[str, float]] = {}
    for qr in results:
        b = dim_buckets.setdefault(qr.dimension, {"earned": 0.0, "max": 0.0, "count": 0.0, "passed": 0.0})
        b["earned"] += qr.score
        b["max"] += qr.max_score
        b["count"] += 1
        b["passed"] += 1 if qr.passed else 0

    total_max = sum(r.max_score for r in results) or 1.0
    total_earned = sum(r.score for r in results)
    score_100 = round((total_earned / total_max) * 100.0, 1)
    tier, tier_label, iq_index = _score_to_tier(score_100)

    dim_scores: dict[str, dict[str, Any]] = {}
    for dkey, vals in dim_buckets.items():
        pct = round((vals["earned"] / max(1.0, vals["max"])) * 100.0, 1)
        dim_scores[dkey] = {
            "label": _DIMENSION_LABELS.get(dkey, dkey),
            "score_pct": pct,
            "earned": round(vals["earned"], 2),
            "max": round(vals["max"], 2),
            "passed": int(vals["passed"]),
            "count": int(vals["count"]),
        }

    mismatch = _check_claimed_tier_mismatch(config.model, score_100, tier)

    iq_summary = IQSummary(
        total_score=score_100,
        iq_index=iq_index,
        tier=tier,
        tier_label=tier_label,
        seed=seed,
        dimension_scores=dim_scores,
        questions=results,
        claimed_tier_mismatch=mismatch,
    )

    evidences: list[EvidenceItem] = []
    if mismatch:
        is_severe = score_100 < 58.0
        evidences.append(
            EvidenceItem(
                id="iq_tier_audit",
                layer="L3_CAPABILITY",
                title="动态反污染智商测评与宣称档位核验",
                status="FAIL" if is_severe else "WARN",
                severity="HIGH" if is_severe else "MEDIUM",
                summary=mismatch,
                details={
                    "score_100": score_100,
                    "iq_index": iq_index,
                    "tier": tier,
                    "seed": seed,
                    "dimensions": dim_scores,
                },
                score_impact=-22 if is_severe else -8,
            )
        )
    else:
        evidences.append(
            EvidenceItem(
                id="iq_tier_audit",
                layer="L3_CAPABILITY",
                title="动态反污染智商测评与宣称档位核验",
                status="PASS" if score_100 >= 70.0 else "INFO",
                severity="INFO",
                summary=(
                    f"动态随机题库实测综合得分 {score_100:.1f}/100（智商指数 {iq_index}，{tier_label}），"
                    f"Seed={seed}，共通过 {sum(1 for r in results if r.passed)}/{len(results)} 题。"
                ),
                details={
                    "score_100": score_100,
                    "iq_index": iq_index,
                    "tier": tier,
                    "seed": seed,
                    "dimensions": dim_scores,
                },
                score_impact=8 if score_100 >= 82.0 else (3 if score_100 >= 68.0 else 0),
            )
        )

    return evidences, iq_summary
