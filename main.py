"""
main.py — AI Fuzzer WebSocket Backend  (v4: Freemium SaaS + Supabase Auth)
════════════════════════════════════════════════════════════════════════════
FastAPI application that exposes a single WebSocket endpoint
(/ws/fuzz) driving the full fuzzing pipeline asynchronously:

  Stage 1 · Compile   — C++: write source & invoke g++ via asyncio
                         subprocess.  Python: write source to victim.py
                         (no compilation step needed).
  Stage 2 · Generate  — call the chosen AI provider with a language-aware
                         prompt to produce crash-inducing payloads.
                         Provider tiers:
                           gemini  — BYOK via google-genai SDK
                           groq    — BYOK via OpenAI-compatible SDK
                           premium — self-hosted Zero-Day Hacker Model
                                     (requires verified Pro JWT)
  Stage 3 · Execute   — pipe each payload through the sandbox:
                           C++:    ./sandbox ./victim
                           Python: ./sandbox python3 victim.py
                         streaming stdout/stderr line-by-line in real time.
  Stage 4 · Triage    — persist CRASH / TIMEOUT artefacts to crashes/

What changed in v4
──────────────────
  • Supabase client initialised from SUPABASE_URL / SUPABASE_ANON_KEY env vars.
  • New "premium" provider tier added to ALLOWED_MODELS.
  • ws_fuzz() extracts "auth_token" from the client payload and forwards it
    to stage_generate().
  • stage_generate() runs a JWT gatekeeper for the premium tier:
      1. Verifies the token via supabase.auth.get_user() (run in a thread).
      2. Checks user_metadata["is_pro"] == True; rejects with a paywall error
         otherwise.
  • api_key validation is now tier-aware: premium requests are not required
    to supply a BYOK key.
  • _call_premium() stub simulates the self-hosted model (asyncio.sleep + 5
    hardcoded payloads) until the real engine is ready to wire in.

What was in v3 (unchanged)
──────────────────────────
  • New "language" field in the client → server payload ("cpp" | "python").
    Defaults to "cpp" when absent for backwards compatibility.
  • Stage 1 skips g++ for Python; writes victim.py instead of victim.cpp.
  • Stage 2 prompt is language-aware: code fence, language name, and
    crash-mode descriptions adapt to the chosen language.
  • Stage 3 invokes python3 instead of the compiled binary for Python targets.
  • Exit-code triage is language-aware.

What was in v2 (unchanged)
──────────────────────────
  • BYOK: client sends api_key, provider, model_id.
  • Multi-provider support: Gemini (google-genai) and Groq (openai SDK).
  • Both BYOK AI calls run inside asyncio.to_thread() — event loop never blocked.
  • JSON sanitisation (_sanitise_llm_json, _extract_json_array).

WebSocket message protocol (server → client):
  {"type": "info",              "message": "..."}
  {"type": "compile_error",     "data": "..."}
  {"type": "payloads_generated","payloads": [...]}
  {"type": "stream",            "source": "stdout"|"stderr", "data": "..."}
  {"type": "result",            "index": N, "payload": "...",
                                "outcome": "CRASH"|"CLEAN"|"TIMEOUT"|"ERROR",
                                "exit_code": N}
  {"type": "done",              "summary": {...}}

WebSocket message protocol (client → server, once on connect):
  {
    "source_code": "<C++ or Python source as a string>",
    "api_key"    : "<provider API key>",      # omit / empty for premium tier
    "provider"   : "gemini" | "groq" | "premium",
    "model_id"   : "<model string>",
    "language"   : "cpp" | "python",          # optional, defaults to "cpp"
    "auth_token" : "<supabase JWT>"           # required for premium tier
  }

Run
───
  pip install fastapi uvicorn websockets google-genai openai supabase
  export SUPABASE_URL="https://<project>.supabase.co"
  export SUPABASE_ANON_KEY="<anon-key>"
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import textwrap
from pathlib import Path
from typing import Any, Literal

# Language type used throughout the pipeline.
Language = Literal["cpp", "python"]

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# ── Supabase client ────────────────────────────────────────────────────────────
#
# Initialised once at module load from environment variables.
# The anon key is safe to use here: we only call supabase.auth.get_user(),
# which validates a JWT against Supabase's public key — it never exposes
# service-role privileges.
#
# If either variable is absent (e.g. local dev without Supabase), the client
# is set to None.  The premium gatekeeper checks for this and returns a
# clear configuration error rather than crashing.

from supabase import create_client, Client as SupabaseClient

def _load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE pairs without requiring python-dotenv."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file(Path(".env"))
_load_env_file(Path("fuzzer-ui/.env"))

_SUPABASE_URL: str | None = (
    os.environ.get("SUPABASE_URL")
    or os.environ.get("VITE_SUPABASE_URL")
)
_SUPABASE_KEY: str | None = (
    os.environ.get("SUPABASE_ANON_KEY")
    or os.environ.get("VITE_SUPABASE_ANON_KEY")
)

supabase: SupabaseClient | None = (
    create_client(_SUPABASE_URL, _SUPABASE_KEY)
    if _SUPABASE_URL and _SUPABASE_KEY
    else None
)

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
log = logging.getLogger("fuzzer")

if supabase is None:
    log.warning(
        "SUPABASE_URL or SUPABASE_ANON_KEY not set — "
        "premium tier will be unavailable."
    )

# ── Constants ──────────────────────────────────────────────────────────────────

SANDBOX_BIN    = "./sandbox"
VICTIM_BIN     = "./victim"       # compiled C++ binary
VICTIM_SRC     = "./victim.cpp"   # C++ source written by stage_compile
VICTIM_PY      = "./victim.py"    # Python source written by stage_compile
CRASHES_DIR    = Path("crashes")
COMPILE_CMD    = ["g++", "-std=c++17", "-O0", "-fno-stack-protector",
                  "-o", VICTIM_BIN, VICTIM_SRC]
NUM_PAYLOADS   = 5
EXEC_TIMEOUT   = 2.0      # seconds per sandbox run
READLINE_LIMIT = 4096     # max bytes per line read from subprocess

# Providers and their allowed model IDs.
# "premium" is the self-hosted Zero-Day Hacker Model tier — it requires a
# verified Pro JWT and does not use a BYOK API key.
ALLOWED_MODELS: dict[str, list[str]] = {
    "gemini": [
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-2.5-pro",
    ],
    "groq": [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
    ],
    "premium": [
        "zero-day-v1",
    ],
}

# Providers that require a BYOK api_key from the client.
# "premium" is intentionally absent: auth is via JWT, not an API key.
BYOK_PROVIDERS: frozenset[str] = frozenset({"gemini", "groq"})

# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "AI Fuzzer Backend",
    description = "Streams real-time fuzzing results over WebSocket.",
    version     = "4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── WebSocket send helpers ─────────────────────────────────────────────────────

async def send(ws: WebSocket, msg: dict[str, Any]) -> None:
    """Serialise and send one JSON message; silently drops on disconnect."""
    try:
        await ws.send_text(json.dumps(msg))
    except Exception:
        pass  # client already gone — the outer handler will catch the disconnect


async def send_info(ws: WebSocket, message: str) -> None:
    log.info("→ info: %s", message)
    await send(ws, {"type": "info", "message": message})


async def send_stream(ws: WebSocket, source: str, data: str) -> None:
    await send(ws, {"type": "stream", "source": source, "data": data})


async def send_result(ws: WebSocket, index: int, payload: str,
                      outcome: str, exit_code: int | None) -> None:
    log.info("→ result[%d]: outcome=%s  exit_code=%s", index, outcome, exit_code)
    await send(ws, {
        "type"     : "result",
        "index"    : index,
        "payload"  : payload,
        "outcome"  : outcome,
        "exit_code": exit_code,
    })


# ── Stage 1: Compile ───────────────────────────────────────────────────────────

async def stage_compile(ws: WebSocket, source_code: str,
                        language: Language) -> bool:
    """
    Stage 1: prepare the target binary or script for execution.

    C++ path
    ────────
    Write source_code to victim.cpp and compile it with g++.  Uses
    asyncio.create_subprocess_exec so the event loop stays live while the
    compiler runs; large projects do not stall other WebSocket sessions.

    Python path
    ───────────
    No compilation is needed.  Write source_code to victim.py and return
    immediately.  The file is executed by python3 inside the sandbox at
    Stage 3.

    Returns True on success, False on any failure (error already streamed).
    """
    if language == "python":
        # ── Python: write script, skip compilation ────────────────────────
        await send_info(ws, "Stage 1 — Writing victim.py (Python — no compilation needed) …")
        try:
            Path(VICTIM_PY).write_text(source_code, encoding="utf-8")
        except OSError as exc:
            await send(ws, {"type": "compile_error",
                            "data": f"Cannot write {VICTIM_PY}: {exc}"})
            return False
        await send_info(ws, f"victim.py written ({len(source_code)} chars).")
        return True

    # ── C++: write source and compile with g++ ────────────────────────────
    await send_info(ws, "Stage 1 — Compiling victim.cpp …")

    try:
        Path(VICTIM_SRC).write_text(source_code, encoding="utf-8")
    except OSError as exc:
        await send(ws, {"type": "compile_error",
                        "data": f"Cannot write {VICTIM_SRC}: {exc}"})
        return False

    try:
        proc = await asyncio.create_subprocess_exec(
            *COMPILE_CMD,
            stdout = asyncio.subprocess.PIPE,
            stderr = asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await proc.communicate()
    except FileNotFoundError:
        await send(ws, {"type": "compile_error",
                        "data": "g++ not found — is build-essential installed?"})
        return False
    except Exception as exc:
        await send(ws, {"type": "compile_error", "data": str(exc)})
        return False

    if proc.returncode != 0:
        error_text = (stderr_b or stdout_b).decode(errors="replace")
        log.warning("Compilation failed:\n%s", error_text)
        await send(ws, {"type": "compile_error", "data": error_text})
        return False

    await send_info(ws, "Compilation succeeded.")
    return True


# ── Stage 2: AI payload generation ────────────────────────────────────────────

def _sanitise_llm_json(raw: str) -> str:
    """
    Repair common LLM JSON encoding errors before attempting to parse.

    Problem: models (especially Llama 3 via Groq) emit C-style hex escapes
    such as \\x00, \\x1b, \\xff when trying to produce binary or non-ASCII
    payloads.  These are valid Python/C string literals but *illegal* in
    JSON, which only allows \\uXXXX Unicode escapes.  json.loads() raises a
    JSONDecodeError the moment it encounters them.

    Fix: rewrite every \\xHH → \\u00HH before any parse attempt.

      \\x00  →  \\u0000   (null byte)
      \\x1b  →  \\u001b   (ESC)
      \\xff  →  \\u00ff   (Latin-1 max)

    The substitution is safe: \\u00HH is semantically identical for the
    U+0000–U+00FF range and is always accepted by json.loads().

    Additional hardening:
      • Strip a leading UTF-8 BOM (\\ufeff) that some providers prepend.
      • Collapse Windows-style CRLF to LF so multi-line regex patterns work
        uniformly regardless of the HTTP transport's line-ending behaviour.
    """
    # Remove BOM if present
    text = raw.lstrip("\ufeff")
    # Normalise line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # C-style hex → JSON unicode:  \xHH  →  \u00HH
    text = re.sub(r"\\x([0-9a-fA-F]{2})", r"\\u00\1", text)
    return text


def _extract_json_array(raw: str) -> list[str]:
    """
    Robustly extract a JSON array from an LLM response string.

    Pipeline:
      0. Sanitise  — convert illegal C-style hex escapes to valid JSON
                     Unicode escapes (\\xHH → \\u00HH) and strip BOMs.
      1. Direct parse          — sanitised response is a clean JSON array.
      2. Markdown fence strip  — remove ```json / ``` wrappers then parse.
      3. Regex hunt            — find the first complete [...] span.

    Each strategy is tried against the *sanitised* text, so the fix applies
    uniformly; we never fall back to the raw, potentially invalid string.

    Raises ValueError (with the first 200 chars of sanitised text for
    debugging) if all three strategies fail.
    """
    # ── Step 0: sanitise once; all strategies operate on `text` ──────────
    text = _sanitise_llm_json(raw.strip())

    log.debug("_extract_json_array: sanitised text[:200] = %r", text[:200])

    # ── Strategy 1: bare JSON ─────────────────────────────────────────────
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return [str(s) for s in result]
    except json.JSONDecodeError:
        pass

    # ── Strategy 2: strip Markdown fences ────────────────────────────────
    stripped = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    stripped = re.sub(r"\s*```\s*$",        "", stripped, flags=re.IGNORECASE)
    try:
        result = json.loads(stripped.strip())
        if isinstance(result, list):
            return [str(s) for s in result]
    except json.JSONDecodeError:
        pass

    # ── Strategy 3: regex hunt for first [...] span ───────────────────────
    match = re.search(r"\[.*?\]", text, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, list):
                return [str(s) for s in result]
        except json.JSONDecodeError:
            pass

    # ── All strategies exhausted ──────────────────────────────────────────
    raise ValueError(
        "Could not extract a valid JSON array from the model response "
        "after sanitisation and three parse strategies.\n"
        f"Sanitised text (first 200 chars): {text[:200]!r}"
    )


def _build_prompt(source_code: str, language: Language) -> str:
    """
    Return the fuzzing prompt — shared by both provider branches.

    The prompt adapts to the target language in three places:
      1. Opening sentence: "C++ program" vs "Python 3 program".
      2. Code fence tag:   ```cpp vs ```python  (helps models with syntax
         highlighting in their context window, slightly improving analysis).
      3. Crash-mode description: C++ lists memory-corruption categories;
         Python lists unhandled-exception categories instead, since Python
         does not SIGSEGV in the same way.

    The CRITICAL hex-escape rule is unchanged — it applies equally to both
    languages because the *output* (the JSON payload array) is always JSON
    regardless of which language the *target* is written in.

    Note: _extract_json_array() applies a regex sanitisation pass as a
    second line of defence regardless of whether the model obeys this rule.
    """
    if language == "python":
        lang_label  = "Python 3"
        fence_tag   = "python"
        crash_modes = textwrap.dedent("""\
            • Unhandled Exception / Crash — ZeroDivisionError, IndexError,
                                            AttributeError, RecursionError,
                                            or any exception that causes the
                                            interpreter to exit non-zero.
              • Infinite Loop / Hang — any input that causes the program to spin
                                       or block forever (while True, unbounded
                                       recursion, etc.).
              • Any other abnormal exit (sys.exit with non-zero, os.abort, etc.).""")
    else:
        lang_label  = "C++"
        fence_tag   = "cpp"
        crash_modes = textwrap.dedent("""\
            • Segmentation Fault  — null pointer dereference, buffer overflow,
                                    stack smash, use-after-free, etc.
              • Infinite Loop / Hang — any input that causes the program to spin
                                       or block forever.
              • Any other undefined behaviour resulting in an abnormal exit.""")

    return textwrap.dedent(f"""\
        You are an expert vulnerability researcher and fuzzing specialist.

        Carefully analyse the following {lang_label} program and identify every
        code path that could lead to a crash or an infinite hang:

```{fence_tag}
        {source_code}
```

        Your task: generate exactly {NUM_PAYLOADS} distinct input strings,
        each designed to trigger one of the following behaviours when passed
        to the program via stdin:

          {crash_modes}

        Guidelines:
          - Each string must be a single line (no embedded newlines).
          - Vary your inputs: do not repeat the same trigger {NUM_PAYLOADS} times.
          - Include at least one CRASH trigger and one LOOP trigger if they
            exist in the code.
          - Include edge-case probes: empty string, very long strings, strings
            with special or non-ASCII characters.
          - CRITICAL: Do not use C-style hex escapes (e.g., \\x00) in your
            JSON strings. Use only standard printable characters or valid JSON
            Unicode escapes (e.g., \\u0000) if non-printable characters are
            necessary. C-style escapes are illegal JSON and will break parsing.
          - CRITICAL: The output must be a single, self-contained, RFC 8259
            compliant JSON array of plain string literals. Every element MUST
            be a fully materialised string — do NOT embed any code, expressions,
            operators, or language constructs inside the array. Specifically:
              * FORBIDDEN: "a" * 100000  (Python expression)
              * FORBIDDEN: "A" + "B"     (string concatenation operator)
              * FORBIDDEN: str(x)        (any function call)
              * FORBIDDEN: any value that is not a quoted string literal
            If you want to represent a long repetitive string, write the actual
            repeated characters inline (e.g., "AAAAAAAAAAAAAAAA...") or shorten
            it to a reasonable length. The JSON parser that reads your output
            has no evaluator — expressions will cause an immediate parse failure.

        Output ONLY a valid JSON array of exactly {NUM_PAYLOADS} strings.
        No markdown fences, no explanations, no text outside the JSON array.
    """)


def _call_gemini(api_key: str, model_id: str, prompt: str) -> str:
    """
    Blocking Gemini call — must be run inside asyncio.to_thread().

    Safety settings: HARM_CATEGORY_DANGEROUS_CONTENT is set to BLOCK_NONE
    so that exploit-generation prompts are not filtered.  This is intentional
    and appropriate: the server is a security research tool, not a consumer
    product.

    We import google.genai inside the function so that servers without the
    package installed can still start and serve the Groq provider.
    """
    from google import genai
    from google.genai import types as genai_types

    client   = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model    = model_id,
        contents = prompt,
        config   = genai_types.GenerateContentConfig(
            safety_settings=[
                genai_types.SafetySetting(
                    category  = "HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold = "BLOCK_NONE",
                ),
            ],
        ),
    )
    return response.text


def _call_groq(api_key: str, model_id: str, prompt: str) -> str:
    """
    Blocking Groq call via the OpenAI-compatible SDK.

    We use a system role instructing the model to act as a vulnerability
    researcher so that it adopts the correct persona before seeing the
    user-supplied C++ code.

    Must be run inside asyncio.to_thread().
    """
    from openai import OpenAI

    client = OpenAI(
        api_key  = api_key,
        base_url = "https://api.groq.com/openai/v1",
    )

    chat = client.chat.completions.create(
        model    = model_id,
        messages = [
            {
                "role"   : "system",
                "content": (
                    "You are an expert vulnerability researcher and fuzzing specialist. "
                    "When asked to analyse C++ or Python code, you respond ONLY with a "
                    "valid JSON array of input strings — no markdown fences, no prose, "
                    "no explanation."
                ),
            },
            {
                "role"   : "user",
                "content": prompt,
            },
        ],
        temperature = 0.7,
    )
    return chat.choices[0].message.content or ""


async def _call_premium(model_id: str, prompt: str) -> str:
    """
    Stub for the self-hosted Zero-Day Hacker Model inference engine.

    This function simulates the network round-trip to the model server with a
    2-second sleep, then returns a hardcoded JSON payload array.  It is async-
    native (no to_thread wrapper needed) so the event loop stays responsive
    while the mock "inference" runs.

    When the real model server is ready, replace the sleep + return below with
    an aiohttp / httpx POST to the inference endpoint, keeping the same
    function signature so the call-site in stage_generate needs no changes.

    The returned string is passed through the same _extract_json_array()
    sanitisation pipeline used for BYOK providers — ensuring the premium path
    is subject to identical output validation.
    """
    log.info("_call_premium: simulating inference for model=%s", model_id)

    # Simulate model latency (replace with real async HTTP call when ready)
    await asyncio.sleep(2)

    # Hardcoded payloads covering the core crash + hang + injection surface:
    #   "CRASH"        — triggers the null-deref / ZeroDivisionError path
    #   "LOOP"         — triggers the infinite-spin path
    #   "A" * 256      — long string for buffer-boundary probing
    #   "admin' --"    — classic SQL / shell injection probe
    #   "%x%x%x%x"    — format-string vulnerability probe
    payloads = ["CRASH", "LOOP", "A" * 256, "admin' --", "%x%x%x%x"]
    return json.dumps(payloads)


def _verify_supabase_user(token: str):  # type: ignore[return]
    """
    Blocking wrapper around supabase.auth.get_user().

    supabase-py v2's auth methods are synchronous.  This function is designed
    to be called exclusively via asyncio.to_thread() so the event loop is
    never blocked by the network round-trip to Supabase's auth endpoint.

    Returns the UserResponse object on success.
    Raises an exception on any failure (invalid token, network error, etc.).
    """
    if supabase is None:
        raise RuntimeError(
            "Supabase client is not configured — "
            "set SUPABASE_URL and SUPABASE_ANON_KEY environment variables."
        )
    # get_user() validates the JWT's signature against Supabase's public key
    # and returns the associated user record.  An invalid or expired token
    # raises gotrue.errors.AuthApiError.
    response = supabase.auth.get_user(token)
    return response


async def stage_generate(
    ws         : WebSocket,
    source_code: str,
    api_key    : str,
    provider   : Literal["gemini", "groq", "premium"],
    model_id   : str,
    language   : Language = "cpp",
    auth_token : str = "",
) -> list[str] | None:
    """
    Call the chosen AI provider to analyse source_code and return payloads.

    Provider routing
    ────────────────
    gemini  — BYOK; offloaded to asyncio.to_thread(_call_gemini)
    groq    — BYOK; offloaded to asyncio.to_thread(_call_groq)
    premium — JWT-gated; calls _call_premium() directly (native async)

    Premium gatekeeper (runs before any inference)
    ───────────────────────────────────────────────
    1. Rejects if auth_token is absent.
    2. Verifies the JWT via supabase.auth.get_user() (in a thread).
    3. Rejects with a paywall error if user_metadata["is_pro"] is not True.

    All three rejection paths stream an "info" error message to the client
    and return None so ws_fuzz() can exit cleanly without a traceback.

    The language parameter is forwarded to _build_prompt so the model
    receives a correctly framed prompt ("C++ program" vs "Python 3 program",
    appropriate code fence, and language-specific crash-mode descriptions).

    Returns None on any failure; the error has already been streamed to the
    client.
    """
    await send_info(ws, f"Stage 2 — Asking {provider}/{model_id} to generate payloads …")

    # ── Premium gatekeeper ─────────────────────────────────────────────────────
    if provider == "premium":

        # 1. Token presence check
        if not auth_token:
            await send_info(
                ws,
                "ERROR: Authentication required for the premium tier. "
                "No auth_token was provided."
            )
            return None

        # 2. JWT verification — run in a thread; supabase-py is blocking
        try:
            user_response = await asyncio.to_thread(_verify_supabase_user, auth_token)
            user = user_response.user
        except Exception as exc:
            # Covers: expired token, tampered token, network failure, misconfigured client
            log.warning("Premium auth failure: %s", exc)
            await send_info(
                ws,
                f"ERROR: Authentication failed — {exc}. "
                "Please log in again and retry."
            )
            return None

        # 3. Pro entitlement check
        # user_metadata is a plain dict; we use .get() with a strict True
        # comparison to prevent any truthy-but-not-pro value from slipping through
        # (e.g. the string "true", the integer 1, or an accidentally set flag).
        is_pro: bool = (
            user is not None
            and isinstance(user.user_metadata, dict)
            and user.user_metadata.get("is_pro") is True
        )
        if not is_pro:
            log.info(
                "Paywall rejection: uid=%s  is_pro=%s",
                getattr(user, "id", "unknown"),
                getattr(user, "user_metadata", {}).get("is_pro") if user else "N/A",
            )
            await send_info(
                ws,
                "ERROR: Upgrade to Pro required. "
                "The Zero-Day Hacker Model is only available on the Pro plan."
            )
            return None

        log.info(
            "Premium access granted: uid=%s",
            getattr(user, "id", "unknown"),
        )

        # 4. Run premium inference (native async — no to_thread needed)
        prompt = _build_prompt(source_code, language)
        try:
            raw_text = await _call_premium(model_id, prompt)
        except Exception as exc:
            await send_info(ws, f"ERROR: Premium model call failed — {exc}")
            log.exception("Premium inference error (model=%s)", model_id)
            return None

    # ── BYOK providers (gemini / groq) ─────────────────────────────────────────
    else:
        prompt = _build_prompt(source_code, language)

        try:
            if provider == "gemini":
                raw_text: str = await asyncio.to_thread(
                    _call_gemini, api_key, model_id, prompt
                )
            elif provider == "groq":
                raw_text = await asyncio.to_thread(
                    _call_groq, api_key, model_id, prompt
                )
            else:
                # Defensive: ws_fuzz validates provider before calling us, but
                # keep this guard in case stage_generate is called directly.
                await send_info(ws, f"ERROR: Unknown provider '{provider}'.")
                return None

        except Exception as exc:
            await send_info(ws, f"ERROR: {provider} API call failed — {exc}")
            log.exception("AI provider error (%s/%s)", provider, model_id)
            return None

    # ── Parse and validate the response (all providers) ───────────────────────
    try:
        payloads = _extract_json_array(raw_text)
    except ValueError as exc:
        await send_info(ws, f"ERROR: Could not parse {provider} response — {exc}")
        return None

    if not payloads:
        await send_info(ws, f"ERROR: {provider} returned an empty payload list.")
        return None

    await send(ws, {"type": "payloads_generated", "payloads": payloads})
    await send_info(ws, f"Generated {len(payloads)} payload(s). "
                        f"Starting sandbox execution …")
    return payloads


# ── Stage 3 & 4: Execute payloads + triage ────────────────────────────────────

async def _drain_stream(
    ws     : WebSocket,
    stream : asyncio.StreamReader,
    source : str,
) -> str:
    """
    Read all remaining bytes from an asyncio StreamReader and stream each
    decoded chunk to the client.  Used to flush pipes after a kill().
    """
    buf: list[str] = []
    try:
        while True:
            chunk = await stream.read(READLINE_LIMIT)
            if not chunk:
                break
            line = chunk.decode(errors="replace")
            buf.append(line)
            await send_stream(ws, source, line)
    except Exception:
        pass
    return "".join(buf)


async def _stream_until_eof(
    ws     : WebSocket,
    stream : asyncio.StreamReader,
    source : str,
) -> str:
    """Read a subprocess stream line-by-line and send each line immediately."""
    buf: list[str] = []
    while True:
        line_bytes = await stream.readline()
        if not line_bytes:
            break
        line = line_bytes.decode(errors="replace")
        buf.append(line)
        await send_stream(ws, source, line)
    return "".join(buf)


def _save_crash(index: int, payload: str, reason: str,
                exit_code: int | None,
                command: str = f"{SANDBOX_BIN} {VICTIM_BIN}") -> Path:
    """Persist a crashing payload + triage note to crashes/."""
    CRASHES_DIR.mkdir(exist_ok=True)
    out_path = CRASHES_DIR / f"payload_{index:03d}.txt"
    note = textwrap.dedent(f"""\
        # Triage Report — payload_{index:03d}
        # ─────────────────────────────────────────────
        # Reason    : {reason}
        # Exit code : {exit_code if exit_code is not None else "N/A"}
        # Command   : {command}
        # ─────────────────────────────────────────────

        {payload}
    """)
    out_path.write_text(note, encoding="utf-8")
    return out_path


async def stage_execute(ws: WebSocket, payloads: list[str],
                        language: Language = "cpp") -> list[dict]:
    """
    Run each payload through the sandbox and triage the results.

    Sandbox command
    ───────────────
    C++:    ./sandbox ./victim
    Python: ./sandbox python3 victim.py

    The sandbox enforces namespace isolation, pivot_root filesystem jail,
    cgroups v2 resource limits, privilege drop, and a seccomp-BPF filter
    regardless of which language is being executed.

    Crash detection
    ───────────────
    C++:    exit code 139 (128 + SIGSEGV) → CRASH.  Other non-zero exits
            that aren't timeouts are classified as ERROR.
    Python: any non-zero exit code → CRASH (unhandled exception / sys.exit
            with non-zero status).  Python does not typically SIGSEGV, but
            any non-zero exit means the interpreter terminated abnormally.

    Design notes
    ────────────
    • asyncio.create_subprocess_exec — fully async; no thread is blocked.
    • Concurrent stream reading via asyncio.gather — stdout and stderr are
      drained simultaneously so neither pipe fills up and deadlocks the child.
    • asyncio.wait_for on proc.wait() — the event loop can service other
      WebSocket connections while we wait for the sandbox to exit.
    • Two-phase kill on timeout — proc.kill() followed by a final gather()
      to drain remaining pipe data and reap the process cleanly.
    """
    results: list[dict] = []

    # Pre-build the sandbox command once — it's the same for every payload.
    if language == "python":
        sandbox_cmd = (SANDBOX_BIN, "python3", VICTIM_PY)
    else:
        sandbox_cmd = (SANDBOX_BIN, VICTIM_BIN)

    for idx, payload in enumerate(payloads):
        await send_info(
            ws,
            f"[{idx + 1}/{len(payloads)}] Testing payload: {payload!r}"
        )

        # ── Launch sandbox ──────────────────────────────────────────────
        try:
            proc = await asyncio.create_subprocess_exec(
                *sandbox_cmd,
                stdin  = asyncio.subprocess.PIPE,
                stdout = asyncio.subprocess.PIPE,
                stderr = asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            await send_info(ws, f"ERROR: Cannot launch sandbox — {exc}")
            results.append({"index": idx, "payload": payload,
                             "outcome": "ERROR", "exit_code": None})
            continue
        except Exception as exc:
            await send_info(ws, f"ERROR: Subprocess launch failed — {exc}")
            results.append({"index": idx, "payload": payload,
                             "outcome": "ERROR", "exit_code": None})
            continue

        # ── Write payload to stdin ──────────────────────────────────────
        try:
            proc.stdin.write((payload + "\n").encode())  # type: ignore[union-attr]
            await proc.stdin.drain()                      # type: ignore[union-attr]
            proc.stdin.close()                            # type: ignore[union-attr]
        except BrokenPipeError:
            pass   # child already exited — will be harvested below
        except Exception as exc:
            log.warning("stdin write error for payload %d: %s", idx, exc)

        # ── Stream stdout + stderr concurrently, then wait ──────────────
        outcome  : str
        exit_code: int | None = None

        stdout_task = asyncio.create_task(
            _stream_until_eof(ws, proc.stdout, "stdout")  # type: ignore[arg-type]
        )
        stderr_task = asyncio.create_task(
            _stream_until_eof(ws, proc.stderr, "stderr")  # type: ignore[arg-type]
        )

        try:
            await asyncio.wait_for(proc.wait(), timeout=EXEC_TIMEOUT)
            await asyncio.gather(stdout_task, stderr_task)
            exit_code = proc.returncode

            # ── Language-aware crash detection ──────────────────────────
            # C++:    exit 139 = 128 + SIGSEGV(11) — memory corruption.
            #         Other non-zero exits are classified ERROR not CRASH
            #         because they may be sandbox or setup failures.
            # Python: any non-zero exit = unhandled exception (CRASH).
            #         The interpreter does not SIGSEGV; non-zero exits
            #         reliably indicate ZeroDivisionError, AttributeError,
            #         RecursionError, sys.exit(n≠0), etc.
            if language == "python":
                if exit_code != 0:
                    outcome = "CRASH"
                else:
                    outcome = "CLEAN"
            else:
                if exit_code == 139:      # 128 + SIGSEGV (11)
                    outcome = "CRASH"
                elif exit_code == 0:
                    outcome = "CLEAN"
                else:
                    outcome = "ERROR"

        except asyncio.TimeoutError:
            proc.kill()
            await asyncio.gather(
                _drain_stream(ws, proc.stdout, "stdout"),  # type: ignore[arg-type]
                _drain_stream(ws, proc.stderr, "stderr"),  # type: ignore[arg-type]
                return_exceptions=True,
            )
            for t in (stdout_task, stderr_task):
                t.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            try:
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            exit_code = proc.returncode
            outcome   = "TIMEOUT"
            await send_info(ws, "[Orchestrator] Infinite loop detected — "
                                "process killed.")

        # ── Triage ──────────────────────────────────────────────────────
        if outcome in ("CRASH", "TIMEOUT"):
            if outcome == "CRASH":
                if language == "python":
                    reason = (
                        f"Unhandled exception / non-zero exit "
                        f"(exit {exit_code}) — check stderr for traceback"
                    )
                else:
                    reason = "SIGSEGV (exit 139) — null-deref or memory corruption"
            else:
                reason = f"HANG — process did not exit within {EXEC_TIMEOUT}s"
            crash_path = _save_crash(idx, payload, reason, exit_code,
                                     " ".join(sandbox_cmd))
            await send_info(ws, f"Crash saved → {crash_path}")

        await send_result(ws, idx, payload, outcome, exit_code)
        results.append({
            "index"    : idx,
            "payload"  : payload,
            "outcome"  : outcome,
            "exit_code": exit_code,
        })

    return results


# ── WebSocket endpoint ─────────────────────────────────────────────────────────

@app.websocket("/ws/fuzz")
async def ws_fuzz(ws: WebSocket) -> None:
    """
    Single WebSocket handler driving the full fuzzing pipeline.

    Expected client message (once, on connect):
      {
        "source_code": "<C++ or Python source as a string>",
        "api_key"    : "<provider API key>",      # empty/omit for premium
        "provider"   : "gemini" | "groq" | "premium",
        "model_id"   : "<model string>",
        "language"   : "cpp" | "python",          # optional, defaults to "cpp"
        "auth_token" : "<supabase JWT>"           # required for premium tier
      }

    The api_key is used only for the duration of this request and is never
    logged or persisted.  The auth_token is verified server-side and also
    never logged.
    """
    await ws.accept()
    log.info("WebSocket connected: %s", ws.client)

    try:
        # ── Receive and validate initial request ─────────────────────────
        try:
            raw = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
        except asyncio.TimeoutError:
            await send_info(ws, "ERROR: Timed out waiting for initial message.")
            return

        try:
            msg = json.loads(raw)

            source_code: str = msg["source_code"]
            if not isinstance(source_code, str) or not source_code.strip():
                raise ValueError("source_code is empty or not a string")

            provider: str = msg.get("provider", "").strip().lower()
            if provider not in ALLOWED_MODELS:
                await send_info(
                    ws,
                    f"ERROR: provider must be one of: "
                    f"{', '.join(ALLOWED_MODELS)}.  Got: {provider!r}"
                )
                return

            model_id: str = msg.get("model_id", "").strip()
            if model_id not in ALLOWED_MODELS[provider]:
                await send_info(
                    ws,
                    f"ERROR: model_id {model_id!r} is not valid for provider "
                    f"'{provider}'.  Allowed: {ALLOWED_MODELS[provider]}"
                )
                return

            # api_key is required only for BYOK providers.
            # For "premium", the JWT (auth_token) is the credential instead;
            # an absent api_key is expected and must not be rejected here.
            api_key: str = msg.get("api_key", "").strip()
            if provider in BYOK_PROVIDERS and not api_key:
                await send_info(ws, "ERROR: api_key is required for BYOK providers.")
                return

            # auth_token is forwarded to stage_generate; the premium gatekeeper
            # there will validate it and check the Pro entitlement flag.
            auth_token: str = msg.get("auth_token", "").strip()

            # language defaults to "cpp" for backwards compatibility with
            # clients that pre-date the polyglot upgrade.
            raw_lang = msg.get("language", "cpp")
            if raw_lang not in ("cpp", "python"):
                await send_info(
                    ws,
                    f"ERROR: language must be 'cpp' or 'python'.  Got: {raw_lang!r}"
                )
                return
            language: Language = raw_lang  # type: ignore[assignment]

        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            await send_info(ws, f"ERROR: Bad request — {exc}")
            return

        log.info(
            "Request: provider=%s  model=%s  language=%s  source_len=%d  "
            "has_api_key=%s  has_auth_token=%s",
            provider, model_id, language, len(source_code),
            bool(api_key), bool(auth_token),
            # NOTE: actual key / token values are intentionally excluded from logs
        )

        # ── Stage 1: Compile / write source ──────────────────────────────
        if not await stage_compile(ws, source_code, language):
            return

        # ── Stage 2: AI generation ───────────────────────────────────────
        payloads = await stage_generate(
            ws          = ws,
            source_code = source_code,
            api_key     = api_key,
            provider    = provider,        # type: ignore[arg-type]
            model_id    = model_id,
            language    = language,
            auth_token  = auth_token,      # forwarded to premium gatekeeper
        )
        if payloads is None:
            return

        # ── Stage 3 + 4: Execute + triage ───────────────────────────────
        results = await stage_execute(ws, payloads, language)

        # ── Done summary ─────────────────────────────────────────────────
        counts: dict[str, int] = {}
        for r in results:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

        await send(ws, {
            "type"   : "done",
            "summary": {"total": len(results), "counts": counts},
        })
        await send_info(ws, "Pipeline complete.")

    except WebSocketDisconnect:
        log.info("Client disconnected early.")

    except Exception as exc:
        log.exception("Unhandled error in ws_fuzz: %s", exc)
        await send_info(ws, f"INTERNAL ERROR: {exc}")

    finally:
        log.info("WebSocket session closed: %s", ws.client)


# ── Health / provider catalogue ────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status"          : "ok",
        "version"         : "4.0.0",
        "supabase_ready"  : supabase is not None,
    }


@app.get("/providers")
async def providers() -> dict[str, Any]:
    """Return the list of supported providers and their models."""
    return {"providers": ALLOWED_MODELS}


# ── Dev entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
