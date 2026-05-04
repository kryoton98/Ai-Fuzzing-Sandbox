#!/usr/bin/env python3
"""
fuzzer.py — v2: AI-Driven Fuzzing Orchestrator
═══════════════════════════════════════════════
Uses the Gemini API to dynamically generate malicious inputs by analysing
the target's source code, then feeds each payload into the sandbox and
triages the results.

Pipeline
────────
  [Gemini API]  ──analysis──▶  [fuzzer.py]  ──stdin──▶  [./sandbox ./victim]
       ▲                            │
       │                     crash triage
  victim.cpp                  crashes/*.txt

Environment
───────────
  GEMINI_API_KEY   — required; the SDK picks this up automatically.

Usage
─────
  python3 fuzzer.py

Requirements
────────────
  pip install google-genai
  Build: g++ -std=c++17 -Wall -Wextra -o sandbox sandbox.cpp
         g++ -std=c++17 -O0 -fno-stack-protector -o victim victim.cpp
"""

import json
import os
import re
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

from google import genai

# ── Configuration ──────────────────────────────────────────────────────────────

SANDBOX_CMD    = ["./sandbox", "./victim"]
TARGET_SOURCE  = "./victim.cpp"
CRASHES_DIR    = Path("crashes")
TIMEOUT_SECS   = 2
MODEL_ID       = "gemini-2.5-flash"
NUM_PAYLOADS   = 5

# ANSI colour helpers — degrade gracefully when stdout is not a tty
_USE_COLOUR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

RED    = lambda t: _c("31;1", t)   # noqa: E731
GREEN  = lambda t: _c("32;1", t)   # noqa: E731
YELLOW = lambda t: _c("33;1", t)   # noqa: E731
CYAN   = lambda t: _c("36;1", t)   # noqa: E731
BOLD   = lambda t: _c("1",    t)   # noqa: E731
DIM    = lambda t: _c("2",    t)   # noqa: E731

# ── UI helpers ─────────────────────────────────────────────────────────────────

def banner(title: str) -> None:
    width = 66
    print()
    print(CYAN("╔" + "═" * (width - 2) + "╗"))
    print(CYAN("║") + BOLD(f"  {title}".ljust(width - 2)) + CYAN("║"))
    print(CYAN("╚" + "═" * (width - 2) + "╝"))


def section(title: str) -> None:
    print()
    print(CYAN("┌─ ") + BOLD(title))
    print(CYAN("│"))


def decode_exit(code: int) -> str:
    """Human-readable exit-code description (128+N → signal name)."""
    if code == 0:
        return GREEN("exit 0  (clean)")
    if code > 128:
        sig_num = code - 128
        try:
            sig_name = signal.Signals(sig_num).name
        except ValueError:
            sig_name = f"SIG#{sig_num}"
        colour = RED if sig_num == signal.SIGSEGV else YELLOW
        return colour(f"exit {code}  (killed by {sig_name})")
    return YELLOW(f"exit {code}  (non-zero)")


# ── File helpers ───────────────────────────────────────────────────────────────

def read_target_source(path: str) -> str:
    """Read the target C++ source, aborting with a clear message on failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
        print(DIM(f"│  ✓ Read {len(source):,} bytes from {path}"))
        return source
    except FileNotFoundError:
        sys.exit(RED(f"[ERROR] Target source not found: {path}"))
    except OSError as exc:
        sys.exit(RED(f"[ERROR] Cannot read {path}: {exc}"))


def save_crash(index: int, payload: str, reason: str, exit_code: int | None) -> Path:
    """Write the crashing payload + triage note to crashes/."""
    CRASHES_DIR.mkdir(exist_ok=True)
    out_path = CRASHES_DIR / f"payload_{index:03d}.txt"
    note = textwrap.dedent(f"""\
        # Triage Report — payload_{index:03d}
        # ─────────────────────────────────────────────
        # Reason    : {reason}
        # Exit code : {exit_code if exit_code is not None else "N/A (process killed)"}
        # Command   : {" ".join(SANDBOX_CMD)}
        # ─────────────────────────────────────────────
        #
        # Payload (raw, one line):

        {payload}
    """)
    out_path.write_text(note, encoding="utf-8")
    return out_path


# ── JSON extraction ────────────────────────────────────────────────────────────

def extract_json_array(raw: str) -> list[str]:
    """
    Robustly extract a JSON array from a model response string.

    LLMs sometimes wrap output in markdown fences, add a preamble sentence,
    or include trailing commentary.  We try three progressively more
    forgiving strategies before giving up:

      1. Direct parse   — the response is already a bare JSON array.
      2. Fence strip    — remove ```json / ``` wrappers, then parse.
      3. Regex hunt     — scan for the first complete '[' … ']' span.
    """
    text = raw.strip()

    # Strategy 1: clean response
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return [str(s) for s in result]
    except json.JSONDecodeError:
        pass

    # Strategy 2: strip markdown code fences
    stripped = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    stripped = re.sub(r"\s*```$",           "", stripped)
    try:
        result = json.loads(stripped.strip())
        if isinstance(result, list):
            return [str(s) for s in result]
    except json.JSONDecodeError:
        pass

    # Strategy 3: extract the outermost [...] block
    match = re.search(r"\[.*?\]", text, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, list):
                return [str(s) for s in result]
        except json.JSONDecodeError:
            pass

    raise ValueError(
        "Could not extract a valid JSON array from the model response.\n"
        f"Raw response (first 600 chars):\n{text[:600]}"
    )


# ── Stage 1: AI payload generation ────────────────────────────────────────────

def generate_payloads(source_code: str) -> list[str]:
    """Ask Gemini to analyse the target source and return fuzzing inputs."""
    section("Stage 1 — AI Payload Generation  [Gemini]")

    prompt = textwrap.dedent(f"""\
        You are an expert vulnerability researcher and fuzzing specialist.

        Carefully analyse the following C++ program and identify every code
        path that could lead to a crash or an infinite hang:

        ```cpp
        {source_code}
        ```

        Your task: generate exactly {NUM_PAYLOADS} distinct input strings,
        each designed to trigger one of the following behaviours when passed
        to the program via stdin:

          • Segmentation Fault  — null pointer dereference, stack/heap
                                  overflow, use-after-free, etc.
          • Infinite Loop / Hang — any input that causes the program to spin
                                   or block forever without producing output.
          • Any undefined behaviour that results in an abnormal exit.

        Guidelines:
          - Each string must be a single line of text (no embedded newlines).
          - Vary your inputs: do not just repeat the same trigger 5 times.
          - Include at least one input targeting CRASH paths and at least one
            targeting LOOP / hang paths if they exist in the code.
          - Keep all individual generated strings strictly under 1,000 characters to prevent JSON truncation.
          - You may also include edge-case probes: empty string, very long
            strings, strings with special characters, off-by-one boundary
            values, or anything that stresses error-handling paths.

        Output ONLY a valid JSON array of exactly {NUM_PAYLOADS} strings.
        Do NOT include markdown fences, explanations, comments, or any text
        outside the JSON array itself.

        Correct format example (do not copy these values):
        ["CRASH", "LOOP", "A" * 10000, "", "\\x00\\x01\\x02"]
    """)

    print(f"│  Model       : {MODEL_ID}")
    print(f"│  Payloads    : {NUM_PAYLOADS} requested")
    print(DIM("│  Contacting Gemini API …"))

    try:
        client   = genai.Client()
        response = client.models.generate_content(
            model    = MODEL_ID,
            contents = prompt,
        )
        raw_text = response.text
    except Exception as exc:
        sys.exit(RED(f"\n[ERROR] Gemini API call failed:\n  {exc}"))

    print(DIM(f"│  ✓ Received {len(raw_text):,} chars from model"))

    try:
        payloads = extract_json_array(raw_text)
    except ValueError as exc:
        sys.exit(RED(f"\n[ERROR] JSON parse failed:\n  {exc}"))

    if not payloads:
        sys.exit(RED("[ERROR] Model returned an empty payload list."))

    print(f"│  {GREEN('✓')} Parsed {len(payloads)} payload(s)")
    print("│")
    for i, p in enumerate(payloads):
        snippet = repr(p) if len(p) <= 55 else repr(p[:52]) + "…'"
        print(f"│    [{i}]  {DIM(snippet)}")

    return payloads


# ── Stage 2: Fuzzing execution loop ───────────────────────────────────────────

def run_fuzzing_loop(payloads: list[str]) -> list[dict]:
    """Feed every payload through the sandbox and record outcomes."""
    section("Stage 2 — Sandbox Execution Loop")

    results = []

    for idx, payload in enumerate(payloads):
        label   = f"payload_{idx:03d}"
        snippet = repr(payload) if len(payload) <= 50 else repr(payload[:47]) + "…'"

        print(f"│  {BOLD(f'[{idx + 1}/{len(payloads)}]')}  {CYAN(label)}")
        print(f"│        Input    : {DIM(snippet)}")

        proc = subprocess.Popen(
            SANDBOX_CMD,
            stdin  = subprocess.PIPE,
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
            text   = True,
        )

        outcome: str
        exit_code: int | None = None
        stdout_buf = ""
        stderr_buf = ""

        try:
            stdout_buf, stderr_buf = proc.communicate(
                input   = payload + "\n",
                timeout = TIMEOUT_SECS,
            )
            exit_code = proc.returncode

            if exit_code == 139:          # 128 + SIGSEGV (11)
                outcome = "CRASH"
            elif exit_code != 0:
                outcome = "ERROR"
            else:
                outcome = "CLEAN"

        except subprocess.TimeoutExpired:
            # The sandbox (and the sandboxed child via its cgroup) must be
            # killed before we drain the pipes — otherwise communicate() hangs.
            proc.kill()
            stdout_buf, stderr_buf = proc.communicate()
            exit_code = proc.returncode
            outcome   = "TIMEOUT"
            print(f"│        {YELLOW('[Orchestrator] Caught infinite loop — process killed')}")

        # ── Per-payload status line ────────────────────────────────────
        _icons = {
            "CRASH"  : RED("✗  CRASH  "),
            "TIMEOUT": YELLOW("⏱  TIMEOUT"),
            "CLEAN"  : GREEN("✓  CLEAN  "),
            "ERROR"  : YELLOW("!  ERROR  "),
        }
        ec_str = decode_exit(exit_code) if exit_code is not None else DIM("—")
        print(f"│        Status   : {_icons[outcome]}")
        print(f"│        Exit code: {ec_str}")

        # Print up to 3 lines from each stream — keeps noisy sandbox logs tidy
        for line in stdout_buf.strip().splitlines()[:3]:
            print(f"│        stdout   : {DIM(line)}")
        for line in stderr_buf.strip().splitlines()[:3]:
            print(f"│        stderr   : {DIM(line)}")
        print("│")

        results.append({
            "index"    : idx,
            "label"    : label,
            "payload"  : payload,
            "outcome"  : outcome,
            "exit_code": exit_code,
        })

    return results


# ── Stage 3: Crash triage ──────────────────────────────────────────────────────

def triage(results: list[dict]) -> None:
    """Persist crashing / hanging payloads to the crashes/ directory."""
    section("Stage 3 — Crash Triage")

    saved = 0
    for r in results:
        if r["outcome"] not in ("CRASH", "TIMEOUT"):
            continue

        if r["outcome"] == "CRASH":
            reason = "SIGSEGV (exit 139) — likely null-deref or memory corruption"
        else:
            reason = f"HANG — process did not exit within {TIMEOUT_SECS}s"

        path = save_crash(r["index"], r["payload"], reason, r["exit_code"])
        print(f"│  {RED('↯')}  {r['label']}  →  {path}")
        print(f"│     {DIM(reason)}")
        saved += 1

    if saved == 0:
        print(f"│  {GREEN('✓')} No crashes or hangs to save.")
    else:
        print("│")
        print(f"│  {RED(f'{saved} crash artefact(s)')} written to  {CRASHES_DIR}/")


# ── Stage 4: Summary table ─────────────────────────────────────────────────────

def print_summary(results: list[dict]) -> None:
    section("Summary")

    _col = {"CRASH": RED, "TIMEOUT": YELLOW, "CLEAN": GREEN, "ERROR": YELLOW}
    counts: dict[str, int] = {}

    header = f"  {'#':<5} {'Label':<16} {'Outcome':<10} {'Exit':>5}  Payload"
    print(header)
    print(DIM("  " + "─" * (len(header))))

    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        colour    = _col.get(r["outcome"], DIM)
        ec_str    = str(r["exit_code"]) if r["exit_code"] is not None else "—"
        snippet   = repr(r["payload"])[:38]
        print(
            f"  {r['index']:<5} {r['label']:<16} "
            f"{colour(r['outcome']):<10} {ec_str:>5}  {DIM(snippet)}"
        )

    print()
    totals = "  │  ".join(
        f"{v}× {_col.get(k, DIM)(k)}" for k, v in sorted(counts.items())
    )
    print(f"  {totals}")
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    banner("AI Fuzzer v2 — Gemini-Driven Sandbox Orchestrator")

    print(f"  Target source  : {TARGET_SOURCE}")
    print(f"  Sandbox command: {' '.join(SANDBOX_CMD)}")
    print(f"  Timeout/payload: {TIMEOUT_SECS}s")
    print(f"  Model          : {MODEL_ID}")
    print(f"  Crash output   : {CRASHES_DIR}/")

    # ── Preflight warnings (non-fatal) ────────────────────────────────────
    if not os.environ.get("GEMINI_API_KEY"):
        print(YELLOW("\n  [WARN] GEMINI_API_KEY not set in environment.\n"
                     "         The Gemini API call will fail without it.\n"
                     "         export GEMINI_API_KEY=<your-key>"))

    for binary in ("./sandbox", "./victim"):
        if not Path(binary).exists():
            print(YELLOW(f"\n  [WARN] {binary} not found — build it first:\n"
                         f"         g++ -std=c++17 -o {binary.lstrip('./')} "
                         f"{binary.lstrip('./') + '.cpp'}"))

    # ── Pipeline ──────────────────────────────────────────────────────────
    source_code = read_target_source(TARGET_SOURCE)
    payloads    = generate_payloads(source_code)
    results     = run_fuzzing_loop(payloads)
    triage(results)
    print_summary(results)

    # Exit code for CI: non-zero if any crash or hang was found
    found_issues = any(r["outcome"] in ("CRASH", "TIMEOUT") for r in results)
    return 1 if found_issues else 0


if __name__ == "__main__":
    sys.exit(main())