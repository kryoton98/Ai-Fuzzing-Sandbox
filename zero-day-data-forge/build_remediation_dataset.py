#!/usr/bin/env python3
"""
build_remediation_dataset.py
════════════════════════════════════════════════════════════════════════════
Builds a ChatML-formatted JSONL training dataset of (vulnerable code →
patched code) pairs for fine-tuning an automated vulnerability remediation
model.

Sources (tried in order, first success wins):
  1. CVEfixes  — CLehmann/CVEfixes  on Hugging Face
                 Function-level diffs linked to NVD CVE records.
                 Fields: code_before, code_after, language, cve_id, cwe_id
  2. BigVul    — multiple known HF slugs tried in sequence
                 C/C++ function-level vulnerability dataset.
                 Fields: func_before, func_after, lang, CVE ID, CWE ID
  3. DiverseVul — DiverseVul/DiverseVul on Hugging Face
                 Diverse C/C++ vulnerability dataset.
                 Fields: func_before, func_after, cve_id

  --demo       Run entirely offline using a small set of curated CWE
               reference examples drawn from NIST/MITRE public pages and
               academic literature.  Useful for pipeline testing without
               a network connection.

Output: remediation_dataset.jsonl  (one JSON object per line, ChatML format)

Usage
─────
  # Pull from HuggingFace (requires internet):
  python build_remediation_dataset.py

  # Specify a particular HF dataset slug:
  python build_remediation_dataset.py --source cvefixes
  python build_remediation_dataset.py --source bigvul

  # Test pipeline offline:
  python build_remediation_dataset.py --demo

  # Limit output size:
  python build_remediation_dataset.py --max-records 5000

  # Combine sources:
  python build_remediation_dataset.py --source cvefixes --source bigvul

Install requirements
────────────────────
  pip install datasets tqdm
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import textwrap
from pathlib import Path
from typing import Iterator

# tqdm is required; datasets is required only for live HF pulls.
try:
    from tqdm import tqdm
except ImportError:
    sys.exit("Missing dependency: pip install tqdm")

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt = "%H:%M:%S",
)
log = logging.getLogger("remediation_builder")

# ── Constants ──────────────────────────────────────────────────────────────────

OUTPUT_FILE   = Path("remediation_dataset.jsonl")
SYSTEM_PROMPT = (
    "You are auto-patch-v1, an elite AI security engineer. "
    "Analyze the provided vulnerable source code and output ONLY the "
    "corrected, secure version of the code that patches the vulnerability."
)

# Minimum / maximum code length (characters) accepted into the dataset.
# Too-short snippets are likely incomplete; too-long ones exceed most
# context windows and add noise without proportional training value.
MIN_CODE_CHARS = 40
MAX_CODE_CHARS = 16_000

# Language values treated as C for the code fence tag
C_LANGS   = {"c", "c99", "c11", "c17"}
CPP_LANGS = {"c++", "cpp", "c++11", "c++14", "c++17", "c++20"}

# ── HuggingFace dataset definitions ───────────────────────────────────────────

# Each entry describes a HuggingFace dataset slug and how to map its fields
# to the canonical (code_before, code_after, language, cve_id, cwe_id) schema.
# Fields listed as None mean "not available in this dataset".
HF_SOURCES: dict[str, dict] = {
    "cvefixes": {
        "slug"        : "CLehmann/CVEfixes",
        "split"       : "train",
        "field_before": "code_before",
        "field_after" : "code_after",
        "field_lang"  : "programming_language",
        "field_cve"   : "cve_id",
        "field_cwe"   : "cwe_id",
        "description" : "CVEfixes — function-level diffs for NVD CVEs (all languages)",
    },
    "bigvul": {
        # Several mirrors exist; we try each in order until one succeeds.
        "slug_candidates": [
            "NeelNanda/BigVul",
            "DLLab/BigVul",
            "benjamin-mcdowell/bigvul",
        ],
        "split"       : "train",
        "field_before": "func_before",
        "field_after" : "func_after",
        "field_lang"  : "lang",
        "field_cve"   : "CVE ID",
        "field_cwe"   : "CWE ID",
        "description" : "BigVul — C/C++ function-level vulnerability dataset",
    },
    "diversevul": {
        "slug"        : "DiverseVul/DiverseVul",
        "split"       : "train",
        "field_before": "func_before",
        "field_after" : "func_after",
        "field_lang"  : None,          # not present; default to "c"
        "field_cve"   : "cve_id",
        "field_cwe"   : None,
        "description" : "DiverseVul — diverse C/C++ vulnerability dataset",
    },
}

# ── Language → code-fence tag ──────────────────────────────────────────────────

def lang_to_fence(lang: str | None) -> str:
    """Map a raw language string to a Markdown code-fence tag."""
    if not lang:
        return "c"
    normalised = lang.strip().lower()
    if normalised in C_LANGS:
        return "c"
    if normalised in CPP_LANGS:
        return "cpp"
    if normalised in {"python", "python3", "py"}:
        return "python"
    if normalised in {"java"}:
        return "java"
    if normalised in {"javascript", "js", "typescript", "ts"}:
        return "javascript"
    if normalised in {"php"}:
        return "php"
    if normalised in {"go", "golang"}:
        return "go"
    if normalised in {"rust"}:
        return "rust"
    # Unknown language — return as-is (lower-cased, spaces removed)
    return normalised.replace(" ", "")


# ── Record validation ──────────────────────────────────────────────────────────

def is_valid_pair(before: str | None, after: str | None) -> bool:
    """
    Return True if the (before, after) pair is suitable for training.

    Rejects:
      • Either field missing or empty
      • Identical before/after (no change was actually made)
      • Either field too short to be a meaningful code snippet
      • Either field too long for a typical context window
    """
    if not before or not after:
        return False
    before = before.strip()
    after  = after.strip()
    if not before or not after:
        return False
    if before == after:
        return False
    if len(before) < MIN_CODE_CHARS or len(after) < MIN_CODE_CHARS:
        return False
    if len(before) > MAX_CODE_CHARS or len(after) > MAX_CODE_CHARS:
        return False
    return True


# ── ChatML record builder ──────────────────────────────────────────────────────

def build_chatml_record(
    code_before: str,
    code_after : str,
    language   : str | None = None,
    cve_id     : str | None = None,
    cwe_id     : str | None = None,
) -> dict:
    """
    Wrap a (before, after) code pair in the ChatML message format.

    The user turn includes a note about the CVE/CWE when available so the
    model can learn to associate vulnerability classes with patch strategies.
    """
    fence = lang_to_fence(language)

    # Build user content — include CVE/CWE context when present
    meta_lines: list[str] = []
    if cve_id:
        meta_lines.append(f"CVE: {cve_id.strip()}")
    if cwe_id:
        meta_lines.append(f"CWE: {str(cwe_id).strip()}")
    meta_block = ("  " + "  ".join(meta_lines) + "\n\n") if meta_lines else ""

    user_content = (
        f"Fix the vulnerability in this code:\n\n"
        f"{meta_block}"
        f"```{fence}\n{code_before.strip()}\n```"
    )

    assistant_content = f"```{fence}\n{code_after.strip()}\n```"

    return {
        "messages": [
            {"role": "system",    "content": SYSTEM_PROMPT},
            {"role": "user",      "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ]
    }


# ── Deduplication helper ───────────────────────────────────────────────────────

def content_hash(before: str, after: str) -> str:
    """SHA-256 of the stripped concatenation — used to skip duplicate pairs."""
    blob = (before.strip() + "|||" + after.strip()).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ── HuggingFace source loader ──────────────────────────────────────────────────

def _load_hf_dataset(slug: str, split: str):
    """Attempt to load a HuggingFace dataset, raising ImportError or the
    underlying HF exception on failure."""
    try:
        from datasets import load_dataset
    except ImportError:
        raise ImportError("Missing dependency: pip install datasets")

    log.info("Connecting to HuggingFace: %s (split=%s) …", slug, split)
    # streaming=True avoids downloading the entire dataset before processing
    return load_dataset(slug, split=split, streaming=True, trust_remote_code=False)


def iter_hf_source(source_key: str) -> Iterator[dict]:
    """
    Yield normalised dicts from a HuggingFace dataset source.
    Normalised keys: code_before, code_after, language, cve_id, cwe_id.
    """
    spec = HF_SOURCES[source_key]

    # Resolve the dataset slug (some sources have candidate mirrors)
    slugs: list[str] = spec.get("slug_candidates", [spec.get("slug")])
    ds = None
    last_error: Exception | None = None

    for slug in slugs:
        try:
            ds = _load_hf_dataset(slug, spec["split"])
            log.info("Loaded: %s", slug)
            break
        except Exception as exc:
            log.warning("  %s — skipping (%s)", slug, exc)
            last_error = exc

    if ds is None:
        raise RuntimeError(
            f"Could not load any slug for source '{source_key}'. "
            f"Last error: {last_error}"
        )

    f_before = spec["field_before"]
    f_after  = spec["field_after"]
    f_lang   = spec.get("field_lang")
    f_cve    = spec.get("field_cve")
    f_cwe    = spec.get("field_cwe")

    for row in ds:
        yield {
            "code_before": row.get(f_before),
            "code_after" : row.get(f_after),
            "language"   : row.get(f_lang)   if f_lang else None,
            "cve_id"     : row.get(f_cve)    if f_cve  else None,
            "cwe_id"     : row.get(f_cwe)    if f_cwe  else None,
        }


# ── Demo dataset (offline) ─────────────────────────────────────────────────────
#
# These examples are drawn from:
#   • MITRE CWE "Demonstrative Examples" (publicly published at cwe.mitre.org)
#   • NIST NVD common vulnerability patterns (nvd.nist.gov)
#   • "Big-Vul" and "CVEfixes" academic paper supplementary materials
#
# They illustrate the most common vulnerability classes in C, C++, and Python
# and are used solely to test the data pipeline without a network connection.
# No novel exploit techniques are included.

DEMO_RECORDS: list[dict] = [
    # ── 1. CWE-120: Buffer Copy Without Checking Size of Input ──────────────
    {
        "code_before": textwrap.dedent("""\
            /* CWE-120 — strcpy without length check */
            void copy_username(char *dest, const char *src) {
                strcpy(dest, src);   /* no bounds check */
            }"""),
        "code_after": textwrap.dedent("""\
            /* Fixed: use strncpy and ensure null-termination */
            #define MAX_NAME 64
            void copy_username(char *dest, const char *src) {
                strncpy(dest, src, MAX_NAME - 1);
                dest[MAX_NAME - 1] = '\\0';
            }"""),
        "language": "c",
        "cve_id": None,
        "cwe_id": "CWE-120",
    },
    # ── 2. CWE-476: NULL Pointer Dereference ─────────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            /* CWE-476 — return value of malloc not checked */
            void process(size_t n) {
                char *buf = (char *)malloc(n);
                buf[0] = 'A';   /* potential NULL dereference */
                free(buf);
            }"""),
        "code_after": textwrap.dedent("""\
            /* Fixed: check malloc return value before use */
            void process(size_t n) {
                char *buf = (char *)malloc(n);
                if (buf == NULL) {
                    perror("malloc");
                    return;
                }
                buf[0] = 'A';
                free(buf);
            }"""),
        "language": "c",
        "cve_id": None,
        "cwe_id": "CWE-476",
    },
    # ── 3. CWE-416: Use-After-Free ────────────────────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            /* CWE-416 — pointer used after free */
            void process_request(Request *req) {
                if (req->error) {
                    free(req->data);
                }
                log_request(req->data);   /* use-after-free when error set */
            }"""),
        "code_after": textwrap.dedent("""\
            /* Fixed: NULL the pointer immediately after free */
            void process_request(Request *req) {
                if (req->error) {
                    free(req->data);
                    req->data = NULL;
                }
                if (req->data != NULL) {
                    log_request(req->data);
                }
            }"""),
        "language": "c",
        "cve_id": None,
        "cwe_id": "CWE-416",
    },
    # ── 4. CWE-190: Integer Overflow ──────────────────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            /* CWE-190 — integer overflow in size calculation */
            char *create_buffer(unsigned int count, unsigned int size) {
                /* count * size can overflow before malloc sees it */
                return (char *)malloc(count * size);
            }"""),
        "code_after": textwrap.dedent("""\
            #include <stdint.h>
            #include <errno.h>
            /* Fixed: use SIZE_MAX check before multiplication */
            char *create_buffer(size_t count, size_t size) {
                if (size != 0 && count > SIZE_MAX / size) {
                    errno = ENOMEM;
                    return NULL;
                }
                return (char *)malloc(count * size);
            }"""),
        "language": "c",
        "cve_id": None,
        "cwe_id": "CWE-190",
    },
    # ── 5. CWE-134: Uncontrolled Format String ────────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            /* CWE-134 — user input passed directly as format string */
            void log_message(const char *user_input) {
                printf(user_input);   /* format string injection */
            }"""),
        "code_after": textwrap.dedent("""\
            /* Fixed: use a literal format string */
            void log_message(const char *user_input) {
                printf("%s", user_input);
            }"""),
        "language": "c",
        "cve_id": None,
        "cwe_id": "CWE-134",
    },
    # ── 6. CWE-122: Heap-Based Buffer Overflow (C++) ──────────────────────────
    {
        "code_before": textwrap.dedent("""\
            // CWE-122 — heap buffer overflow via unchecked operator[]
            #include <vector>
            int get_element(std::vector<int>& v, size_t idx) {
                return v[idx];   // no bounds check; UB if idx >= v.size()
            }"""),
        "code_after": textwrap.dedent("""\
            // Fixed: use at() which throws std::out_of_range on bad index
            #include <vector>
            #include <stdexcept>
            int get_element(std::vector<int>& v, size_t idx) {
                return v.at(idx);
            }"""),
        "language": "cpp",
        "cve_id": None,
        "cwe_id": "CWE-122",
    },
    # ── 7. CWE-401: Memory Leak (C++) ─────────────────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            // CWE-401 — raw new without matching delete on error path
            #include <string>
            void handle(const std::string& s) {
                char *buf = new char[s.size() + 1];
                if (s.empty()) {
                    return;   // leak: buf never deleted on this path
                }
                std::copy(s.begin(), s.end(), buf);
                buf[s.size()] = '\\0';
                process(buf);
                delete[] buf;
            }"""),
        "code_after": textwrap.dedent("""\
            // Fixed: use std::unique_ptr for automatic cleanup
            #include <string>
            #include <memory>
            void handle(const std::string& s) {
                auto buf = std::make_unique<char[]>(s.size() + 1);
                if (s.empty()) {
                    return;   // unique_ptr destructor runs automatically
                }
                std::copy(s.begin(), s.end(), buf.get());
                buf[s.size()] = '\\0';
                process(buf.get());
            }"""),
        "language": "cpp",
        "cve_id": None,
        "cwe_id": "CWE-401",
    },
    # ── 8. CWE-22: Path Traversal (Python) ───────────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            # CWE-22 — path traversal via unsanitised user input
            import os

            BASE_DIR = "/var/www/uploads"

            def read_file(filename: str) -> bytes:
                path = os.path.join(BASE_DIR, filename)
                with open(path, "rb") as f:   # ../../etc/passwd possible
                    return f.read()"""),
        "code_after": textwrap.dedent("""\
            # Fixed: resolve and validate the path stays within BASE_DIR
            import os

            BASE_DIR = os.path.realpath("/var/www/uploads")

            def read_file(filename: str) -> bytes:
                path = os.path.realpath(os.path.join(BASE_DIR, filename))
                if not path.startswith(BASE_DIR + os.sep):
                    raise ValueError(f"Access denied: {filename!r}")
                with open(path, "rb") as f:
                    return f.read()"""),
        "language": "python",
        "cve_id": None,
        "cwe_id": "CWE-22",
    },
    # ── 9. CWE-89: SQL Injection (Python) ────────────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            # CWE-89 — SQL query built by string formatting
            import sqlite3

            def get_user(db: sqlite3.Connection, username: str):
                query = f"SELECT * FROM users WHERE name = '{username}'"
                return db.execute(query).fetchone()"""),
        "code_after": textwrap.dedent("""\
            # Fixed: parameterised query — user input never interpolated
            import sqlite3

            def get_user(db: sqlite3.Connection, username: str):
                query = "SELECT * FROM users WHERE name = ?"
                return db.execute(query, (username,)).fetchone()"""),
        "language": "python",
        "cve_id": None,
        "cwe_id": "CWE-89",
    },
    # ── 10. CWE-78: OS Command Injection (Python) ─────────────────────────────
    {
        "code_before": textwrap.dedent("""\
            # CWE-78 — shell=True with user-controlled input
            import subprocess

            def ping_host(host: str) -> str:
                result = subprocess.run(
                    f"ping -c 1 {host}", shell=True, capture_output=True
                )
                return result.stdout.decode()"""),
        "code_after": textwrap.dedent("""\
            # Fixed: shell=False with argument list; no shell metachar risk
            import subprocess
            import re

            _HOSTNAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')

            def ping_host(host: str) -> str:
                if not _HOSTNAME_RE.match(host):
                    raise ValueError(f"Invalid hostname: {host!r}")
                result = subprocess.run(
                    ["ping", "-c", "1", host],
                    shell=False, capture_output=True, timeout=5
                )
                return result.stdout.decode()"""),
        "language": "python",
        "cve_id": None,
        "cwe_id": "CWE-78",
    },
]


def iter_demo_source() -> Iterator[dict]:
    """Yield normalised dicts from the offline demo set."""
    for rec in DEMO_RECORDS:
        yield {
            "code_before": rec["code_before"],
            "code_after" : rec["code_after"],
            "language"   : rec.get("language"),
            "cve_id"     : rec.get("cve_id"),
            "cwe_id"     : rec.get("cwe_id"),
        }


# ── Main pipeline ──────────────────────────────────────────────────────────────

def build_dataset(
    sources     : list[str],
    output_path : Path,
    max_records : int | None,
    demo_mode   : bool,
) -> None:
    seen_hashes: set[str] = set()
    written = 0
    skipped_invalid = 0
    skipped_duplicate = 0

    # Build an iterator over raw (un-normalised) records from each source
    def all_records() -> Iterator[dict]:
        if demo_mode:
            log.info("Running in DEMO mode — using offline CWE reference examples.")
            yield from iter_demo_source()
            return

        for src_key in sources:
            if src_key not in HF_SOURCES:
                log.warning("Unknown source '%s' — skipping.", src_key)
                continue
            desc = HF_SOURCES[src_key]["description"]
            log.info("─" * 60)
            log.info("Source: %s", desc)
            try:
                yield from iter_hf_source(src_key)
            except Exception as exc:
                log.error("Failed to load source '%s': %s", src_key, exc)
                log.error("Skipping this source and continuing.")

    # Progress bar — indeterminate total when streaming
    pbar = tqdm(
        all_records(),
        desc    = "Processing records",
        unit    = " records",
        dynamic_ncols = True,
    )

    with output_path.open("w", encoding="utf-8") as out_fh:
        for raw in pbar:
            if max_records is not None and written >= max_records:
                log.info("Reached --max-records limit (%d).", max_records)
                break

            before = raw.get("code_before") or ""
            after  = raw.get("code_after")  or ""
            lang   = raw.get("language")
            cve    = raw.get("cve_id")
            cwe    = raw.get("cwe_id")

            # Validate
            if not is_valid_pair(before, after):
                skipped_invalid += 1
                pbar.set_postfix(written=written, invalid=skipped_invalid,
                                 dup=skipped_duplicate)
                continue

            # Deduplicate
            h = content_hash(before, after)
            if h in seen_hashes:
                skipped_duplicate += 1
                pbar.set_postfix(written=written, invalid=skipped_invalid,
                                 dup=skipped_duplicate)
                continue
            seen_hashes.add(h)

            # Build and write ChatML record
            record = build_chatml_record(
                code_before = before,
                code_after  = after,
                language    = lang,
                cve_id      = cve,
                cwe_id      = cwe,
            )
            out_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1
            pbar.set_postfix(written=written, invalid=skipped_invalid,
                             dup=skipped_duplicate)

    pbar.close()

    log.info("═" * 60)
    log.info("Output file  : %s", output_path.resolve())
    log.info("Written      : %d records", written)
    log.info("Skipped      : %d invalid,  %d duplicates",
             skipped_invalid, skipped_duplicate)
    log.info("═" * 60)

    if written == 0:
        log.warning(
            "No records were written.  "
            "If using a live HF source, check your internet connection "
            "and dataset slug.  Use --demo to test the pipeline offline."
        )


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description = "Build a ChatML remediation dataset from vulnerability databases.",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent("""\
            Examples:
              python build_remediation_dataset.py --demo
              python build_remediation_dataset.py --source cvefixes
              python build_remediation_dataset.py --source cvefixes --source bigvul
              python build_remediation_dataset.py --source bigvul --max-records 10000
        """),
    )
    parser.add_argument(
        "--source",
        choices = list(HF_SOURCES.keys()),
        action  = "append",
        default = [],
        dest    = "sources",
        metavar = "SOURCE",
        help    = (
            "HuggingFace dataset source to pull from.  "
            "May be specified multiple times.  "
            f"Choices: {', '.join(HF_SOURCES)}.  "
            "Default: all sources tried in order."
        ),
    )
    parser.add_argument(
        "--output",
        type    = Path,
        default = OUTPUT_FILE,
        help    = f"Output JSONL file path (default: {OUTPUT_FILE})",
    )
    parser.add_argument(
        "--max-records",
        type    = int,
        default = None,
        metavar = "N",
        help    = "Stop after writing N records (default: no limit)",
    )
    parser.add_argument(
        "--demo",
        action  = "store_true",
        help    = "Run offline using built-in CWE reference examples only",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Default to all sources when none specified
    sources = args.sources if args.sources else list(HF_SOURCES.keys())

    if not args.demo:
        log.info("Sources requested: %s", ", ".join(sources))
        log.info("Output file      : %s", args.output)
        if args.max_records:
            log.info("Max records      : %d", args.max_records)

    build_dataset(
        sources     = sources,
        output_path = args.output,
        max_records = args.max_records,
        demo_mode   = args.demo,
    )


if __name__ == "__main__":
    main()