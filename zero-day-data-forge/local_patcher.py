"""
local_patcher.py — AUTO-PATCH-V2 Secure Terminal
─────────────────────────────────────────────────
Loads a 4-bit quantised Llama-3-8B-Instruct with a LoRA adapter
and patches vulnerable code snippets interactively.

Tuned for 6 GB VRAM (RTX 4050) + WSL2 with 12 GB RAM budget.

Key memory fixes vs. the original:
  1. low_cpu_mem_usage=True  — skips the 16 GB RAM spike by loading
     weights directly into quantised format layer-by-layer instead of
     buffering the full fp16 checkpoint in system RAM first.
  2. Explicit torch.cuda.empty_cache() between inferences so fragmented
     VRAM from the previous run is reclaimed before the next generate().
  3. Streamed token generation via TextStreamer so you see output as it
     is produced rather than waiting for the full response — if the
     process is killed mid-generate you still get partial output.
  4. Tighter max_memory ceiling (4.5 GiB GPU) to leave headroom for
     CUDA kernels and the KV-cache, which are not counted in the weight
     footprint but still compete for VRAM.
"""

import gc
import sys
import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TextStreamer,
)
from peft import PeftModel

# ── Configuration ──────────────────────────────────────────────────────────────

MODEL_ID    = "NousResearch/Meta-Llama-3-8B-Instruct"
ADAPTER_DIR = "./auto-patch-v2-adapter"

# How many new tokens the model may emit per response.
# 512 comfortably covers most function-level patches; raise if you need more.
MAX_NEW_TOKENS = 512

SYSTEM_PROMPT = (
    "You are auto-patch-v2, an elite AI security engineer. "
    "Analyze the provided vulnerable source code and output ONLY the "
    "corrected, secure version of the code that patches the vulnerability. "
    "Add a brief comment above each changed line explaining what was fixed."
)

# ── 4-bit quantisation config ─────────────────────────────────────────────────

bnb_config = BitsAndBytesConfig(
    load_in_4bit             = True,
    bnb_4bit_use_double_quant= True,   # nested quantisation: saves ~0.4 GB
    bnb_4bit_quant_type      = "nf4",  # NormalFloat4 — best quality for LLMs
    bnb_4bit_compute_dtype   = torch.bfloat16,
    llm_int8_enable_fp32_cpu_offload = True,
)

# ── Load tokeniser ─────────────────────────────────────────────────────────────

print("📦  Loading tokeniser…")
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

# Llama-3 has no default pad token; set it to eos so batch padding works
# (matters if you later add batching; harmless for interactive use).
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# ── Load base model ────────────────────────────────────────────────────────────

print("🧠  Loading 4-bit base model…")
print("    (low_cpu_mem_usage=True — no 16 GB RAM spike this time)\n")

base_model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    quantization_config = bnb_config,
    device_map          = "auto",

    # ── THE CRITICAL FIX ──────────────────────────────────────────────────────
    # Without this flag transformers buffers the entire fp16 checkpoint
    # (~16 GB) in system RAM before quantising.  low_cpu_mem_usage=True
    # switches to a lazy, layer-by-layer approach: each tensor is loaded,
    # quantised, moved to its target device, and then freed — peak RAM
    # usage stays well under 4 GB regardless of the model's disk size.
    low_cpu_mem_usage   = True,

    # Tighter VRAM ceiling than the original 5 GiB.
    # CUDA kernels + KV-cache need ~0.5–1 GB of VRAM that is NOT counted
    # in the weight footprint.  Leaving 1.5 GB of headroom prevents OOM
    # errors during generate() even for long prompts.
    max_memory          = {0: "4500MiB", "cpu": "11GiB"},
)

# ── Attach LoRA adapter ────────────────────────────────────────────────────────

print("\n💉  Attaching auto-patch-v2 adapter…")
model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
model.eval()   # disable dropout — not needed for inference, saves a tiny bit

# Frees any staging tensors left over from the load + adapter merge.
gc.collect()
torch.cuda.empty_cache()

vram_used = torch.cuda.memory_allocated() / 1024**3
vram_res  = torch.cuda.memory_reserved()  / 1024**3
print(f"\n✅  Model ready  —  VRAM used: {vram_used:.2f} GB  |  reserved: {vram_res:.2f} GB")

# ── Interactive terminal ───────────────────────────────────────────────────────

print("\n" + "═" * 60)
print("  🤖  AUTO-PATCH-V2  ·  SECURE TERMINAL  ·  LOCAL-6GB")
print("═" * 60)
print("Paste vulnerable code, then press Enter twice to submit.")
print("Type 'exit' or press Ctrl-C to quit.\n")

# TextStreamer writes tokens to stdout as they are generated.
# This means you see the patched code character-by-character rather than
# waiting for the full response — much better UX, and if you hit Ctrl-C
# mid-generate you still have the partial patch.
streamer = TextStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)

while True:
    try:
        # ── Collect multi-line input (blank line = end of input) ───────────────
        print("\n[VULNERABLE CODE] >>> (blank line to submit)")
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                # Handle piped / non-interactive input
                sys.exit(0)
            if line.lower() == "exit":
                print("👋  Goodbye.")
                sys.exit(0)
            if line == "" and lines:
                break
            lines.append(line)

        user_code = "\n".join(lines).strip()
        if not user_code:
            print("  (empty input — skipping)")
            continue

        # ── Build ChatML prompt ────────────────────────────────────────────────
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": f"Fix the vulnerability in this code:\n\n```\n{user_code}\n```"},
        ]
        prompt  = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs  = tokenizer(prompt, return_tensors="pt").to(model.device)
        n_input = inputs.input_ids.shape[-1]

        # ── Generate ───────────────────────────────────────────────────────────
        print("\n[PATCHING…]\n" + "─" * 60)
        print("🛡️  SECURE CODE:\n")

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens = MAX_NEW_TOKENS,
                temperature    = 0.1,     # near-deterministic: good for code
                do_sample      = True,
                repetition_penalty = 1.1, # mild penalty to avoid looping
                streamer       = streamer,
            )

        print("\n" + "─" * 60)

        # ── Log token counts for diagnostics ──────────────────────────────────
        n_out = outputs.shape[-1] - n_input
        print(f"  [tokens: {n_input} in → {n_out} out]")

        # ── Reclaim VRAM between runs ──────────────────────────────────────────
        # The KV-cache from this generate() call is still allocated.
        # Freeing it explicitly keeps the memory footprint flat across
        # multiple patches in the same session.
        del outputs, inputs
        gc.collect()
        torch.cuda.empty_cache()

    except KeyboardInterrupt:
        print("\n\n👋  Interrupted.  Goodbye.")
        break
    except torch.cuda.OutOfMemoryError:
        print("\n⚠️  VRAM OOM during generate().")
        print("   Try a shorter code snippet, or reduce MAX_NEW_TOKENS at the top of the script.")
        gc.collect()
        torch.cuda.empty_cache()
    except Exception as exc:
        print(f"\n⚠️  Unexpected error: {exc}")