/**
 * App.tsx — AI Fuzzer Dashboard  (v2: BYOK Multi-Provider)
 * ════════════════════════════════════════════════════════════════
 * Single-file React dashboard for the AI-driven fuzzing pipeline.
 *
 * What changed in v2
 * ──────────────────
 * · New "AI Configuration" section above the code editor:
 *     - Provider dropdown  : Gemini | Groq
 *     - Model dropdown     : filtered by selected provider
 *     - API Key input      : password field, never logged
 * · WebSocket send payload now includes api_key, provider, model_id.
 * · Terminal shows which provider/model is active at launch.
 *
 * Stack requirements (package.json):
 *   react, react-dom, typescript
 *   tailwindcss
 *   @xterm/xterm  @xterm/addon-fit  @xterm/addon-web-links
 *   lucide-react
 *
 * CSS (index.css / globals.css) — add once:
 *   @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');
 *   @import '@xterm/xterm/css/xterm.css';
 */

import {
  useEffect,
  useRef,
  useState,
  useCallback,
  type FC,
  type ChangeEvent,
} from "react";
import { Terminal as XTerm }   from "@xterm/xterm";
import { FitAddon }            from "@xterm/addon-fit";
import { WebLinksAddon }       from "@xterm/addon-web-links";
import {
  Bug,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CircleDot,
  Clock,
  Eye,
  EyeOff,
  FlaskConical,
  KeyRound,
  Loader2,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Wifi,
  WifiOff,
  Zap,
} from "lucide-react";

// ── Constants ──────────────────────────────────────────────────────────────────

const WS_URL = "ws://127.0.0.1:8000/ws/fuzz";

/** Provider → allowed models map (mirrors ALLOWED_MODELS in main.py) */
const PROVIDER_MODELS: Record<string, string[]> = {
  gemini: ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.5-pro"],
  groq  : ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
};

const DEFAULT_SOURCE = `#include <iostream>
#include <string>

int main() {
    std::string input;
    if (!std::getline(std::cin, input)) {
        std::cerr << "[victim] stdin closed\\n";
        return 1;
    }

    // Trigger 1: deliberate null-dereference -> SIGSEGV
    if (input == "CRASH") {
        std::cerr << "[victim] CRASH -> triggering SIGSEGV\\n";
        volatile int *p = nullptr;
        *p = 0xDEAD;
        return 0;
    }

    // Trigger 2: infinite spin -> timeout / SIGKILL
    if (input == "LOOP") {
        std::cerr << "[victim] LOOP -> spinning forever\\n";
        volatile bool spin = true;
        while (spin) {}
        return 0;
    }

    std::cout << "Safe: " << input << "\\n";
    return 0;
}`;

// ANSI escape sequences for xterm colouring
const ANSI = {
  reset   : "\x1b[0m",
  bold    : "\x1b[1m",
  dim     : "\x1b[2m",
  red     : "\x1b[31m",
  green   : "\x1b[32m",
  yellow  : "\x1b[33m",
  blue    : "\x1b[34m",
  cyan    : "\x1b[36m",
  bRed    : "\x1b[91m",
  bGreen  : "\x1b[92m",
  bYellow : "\x1b[93m",
  bCyan   : "\x1b[96m",
  bWhite  : "\x1b[97m",
  magenta : "\x1b[35m",
};

// ── Types ──────────────────────────────────────────────────────────────────────

type Provider   = "gemini" | "groq";
type Outcome    = "CRASH" | "CLEAN" | "TIMEOUT" | "ERROR" | "PENDING";
type FuzzerStatus =
  | "idle" | "connecting" | "compiling"
  | "generating" | "fuzzing" | "done" | "error";

interface FuzzResult {
  index   : number;
  payload : string;
  outcome : Outcome;
  exitCode: number | null;
}

// ── Small UI primitives ────────────────────────────────────────────────────────

function outcomeColor(o: Outcome): string {
  return o === "CRASH"   ? "text-red-400"
       : o === "TIMEOUT" ? "text-yellow-400"
       : o === "CLEAN"   ? "text-emerald-400"
       : o === "ERROR"   ? "text-orange-400"
       :                   "text-zinc-500";
}

function outcomeBg(o: Outcome): string {
  return o === "CRASH"   ? "bg-red-950/60    border-red-800/40"
       : o === "TIMEOUT" ? "bg-yellow-950/60 border-yellow-800/40"
       : o === "CLEAN"   ? "bg-emerald-950/60 border-emerald-800/40"
       : o === "ERROR"   ? "bg-orange-950/60 border-orange-800/40"
       :                   "bg-zinc-900/40   border-zinc-700/30";
}

function OutcomeIcon({ outcome }: { outcome: Outcome }) {
  const cls = `w-3.5 h-3.5 ${outcomeColor(outcome)}`;
  if (outcome === "CRASH")   return <ShieldAlert className={cls} />;
  if (outcome === "TIMEOUT") return <Clock       className={cls} />;
  if (outcome === "CLEAN")   return <CircleCheck className={cls} />;
  if (outcome === "ERROR")   return <CircleAlert className={cls} />;
  return <CircleDot className={`${cls} animate-pulse`} />;
}

// ── Shared form-control styles ─────────────────────────────────────────────────

const selectCls = `
  w-full bg-[#050508] border border-zinc-800/70 rounded
  px-2.5 py-1.5 text-xs font-mono text-zinc-200
  appearance-none cursor-pointer
  focus:outline-none focus:border-emerald-800/60 focus:ring-1 focus:ring-emerald-900/40
  transition-colors duration-150
  disabled:opacity-40 disabled:cursor-not-allowed
`.trim();

const inputCls = `
  w-full bg-[#050508] border border-zinc-800/70 rounded
  px-2.5 py-1.5 text-xs font-mono text-zinc-200
  placeholder-zinc-700
  focus:outline-none focus:border-emerald-800/60 focus:ring-1 focus:ring-emerald-900/40
  transition-colors duration-150
  disabled:opacity-40 disabled:cursor-not-allowed
`.trim();

// ── Main Component ─────────────────────────────────────────────────────────────

const App: FC = () => {

  // ── Refs ──────────────────────────────────────────────────────────────────
  const terminalDivRef = useRef<HTMLDivElement>(null);
  const xtermRef       = useRef<XTerm | null>(null);
  const fitAddonRef    = useRef<FitAddon | null>(null);
  const wsRef          = useRef<WebSocket | null>(null);
  const roRef          = useRef<ResizeObserver | null>(null);

  // ── Core fuzzer state ─────────────────────────────────────────────────────
  const [sourceCode, setSourceCode] = useState<string>(DEFAULT_SOURCE);
  const [status,     setStatus    ] = useState<FuzzerStatus>("idle");
  const [results,    setResults   ] = useState<FuzzResult[]>([]);
  const [statusMsg,  setStatusMsg ] = useState<string>("Ready to fuzz.");

  // ── AI Configuration state ─────────────────────────────────────────────────
  const [provider,    setProvider   ] = useState<Provider>("gemini");
  const [modelId,     setModelId    ] = useState<string>(PROVIDER_MODELS.gemini[0]);
  const [apiKey,      setApiKey     ] = useState<string>("");
  const [showApiKey,  setShowApiKey ] = useState<boolean>(false);

  // When the provider changes, reset modelId to the first model of that provider
  const handleProviderChange = useCallback((e: ChangeEvent<HTMLSelectElement>) => {
    const p = e.target.value as Provider;
    setProvider(p);
    setModelId(PROVIDER_MODELS[p][0]);
  }, []);

  // ── xterm initialisation ──────────────────────────────────────────────────
  useEffect(() => {
    if (!terminalDivRef.current) return;

    const term = new XTerm({
      theme: {
        background         : "#0a0a0f",
        foreground         : "#b4c2b4",
        cursor             : "#39ff14",
        cursorAccent       : "#0a0a0f",
        selectionBackground: "#39ff1430",
        black              : "#1a1a2e",
        red                : "#ff4444",
        green              : "#39ff14",
        yellow             : "#ffcc00",
        blue               : "#4488ff",
        magenta            : "#dd44ff",
        cyan               : "#00e5ff",
        white              : "#b4c2b4",
        brightBlack        : "#444466",
        brightRed          : "#ff6666",
        brightGreen        : "#66ff44",
        brightYellow       : "#ffdd44",
        brightBlue         : "#66aaff",
        brightMagenta      : "#ee66ff",
        brightCyan         : "#44eeff",
        brightWhite        : "#ddeedd",
      },
      fontFamily      : "'Share Tech Mono', 'Courier New', monospace",
      fontSize        : 12,
      lineHeight      : 1.4,
      letterSpacing   : 0.3,
      cursorBlink     : true,
      cursorStyle     : "block",
      scrollback      : 5000,
      allowProposedApi: true,
    });

    const fit   = new FitAddon();
    const links = new WebLinksAddon();
    term.loadAddon(fit);
    term.loadAddon(links);
    term.open(terminalDivRef.current);
    fit.fit();

    xtermRef.current    = term;
    fitAddonRef.current = fit;

    term.writeln(`${ANSI.dim}${ANSI.green}┌──────────────────────────────────────────────┐${ANSI.reset}`);
    term.writeln(`${ANSI.green}  AI FUZZER TERMINAL  ${ANSI.dim}v2.0  · BYOK${ANSI.reset}`);
    term.writeln(`${ANSI.dim}${ANSI.green}└──────────────────────────────────────────────┘${ANSI.reset}`);
    term.writeln(`${ANSI.dim}Select a provider, enter your API key, and launch.${ANSI.reset}`);

    const ro = new ResizeObserver(() => fit.fit());
    ro.observe(terminalDivRef.current);
    roRef.current = ro;

    return () => {
      ro.disconnect();
      term.dispose();
      xtermRef.current    = null;
      fitAddonRef.current = null;
    };
  }, []);

  // ── xterm write helpers ───────────────────────────────────────────────────
  const termWriteln = useCallback((line: string) => {
    xtermRef.current?.writeln(line);
  }, []);
  const termWrite   = useCallback((text: string) => {
    xtermRef.current?.write(text);
  }, []);
  const termClear   = useCallback(() => {
    xtermRef.current?.clear();
  }, []);

  // ── WebSocket message handler ──────────────────────────────────────────────
  const handleMessage = useCallback((raw: string) => {
    let msg: Record<string, unknown>;
    try { msg = JSON.parse(raw); }
    catch { termWriteln(`${ANSI.dim}[raw] ${raw}${ANSI.reset}`); return; }

    switch (msg.type) {

      case "info": {
        const text = String(msg.message ?? "");
        termWriteln(`${ANSI.dim}${ANSI.blue}ℹ ${ANSI.reset}${ANSI.dim}${text}${ANSI.reset}`);
        setStatusMsg(text.slice(0, 120));
        if (/stage 1|compil/i.test(text))           setStatus("compiling");
        else if (/stage 2|gemini|groq|generat/i.test(text)) setStatus("generating");
        else if (/stage 3|sandbox|execut/i.test(text))      setStatus("fuzzing");
        else if (/pipeline complete/i.test(text))           setStatus("done");
        else if (/error/i.test(text))                       setStatus("error");
        break;
      }

      case "compile_error": {
        const data = String(msg.data ?? "");
        termWriteln("");
        termWriteln(`${ANSI.bRed}${ANSI.bold}✗  COMPILATION FAILED${ANSI.reset}`);
        data.split("\n").forEach(l =>
          termWriteln(`${ANSI.red}  ${l}${ANSI.reset}`)
        );
        setStatus("error");
        setStatusMsg("Compilation failed.");
        wsRef.current?.close();
        break;
      }

      case "stream": {
        const src    = String(msg.source ?? "stdout");
        const data   = String(msg.data   ?? "");
        const colour = src === "stderr" ? ANSI.yellow : ANSI.dim;
        termWrite(`${colour}${data}${ANSI.reset}`);
        break;
      }

      case "payloads_generated": {
        const payloads = Array.isArray(msg.payloads) ? msg.payloads as string[] : [];
        termWriteln("");
        termWriteln(`${ANSI.bCyan}${ANSI.bold}⚡ Payloads generated (${payloads.length})${ANSI.reset}`);
        payloads.forEach((p, i) => {
          const snippet = p.length > 60 ? `${p.slice(0, 57)}…` : p;
          termWriteln(`${ANSI.dim}  [${i}] ${ANSI.cyan}${snippet}${ANSI.reset}`);
        });
        termWriteln("");
        setResults(payloads.map((p, i) => ({
          index: i, payload: p, outcome: "PENDING", exitCode: null,
        })));
        setStatus("fuzzing");
        break;
      }

      case "result": {
        const index    = Number(msg.index    ?? 0);
        const payload  = String(msg.payload  ?? "");
        const outcome  = String(msg.outcome  ?? "ERROR") as Outcome;
        const exitCode = msg.exit_code != null ? Number(msg.exit_code) : null;
        const icons: Record<Outcome, string> = {
          CRASH  : `${ANSI.bRed}${ANSI.bold}✗ CRASH${ANSI.reset}`,
          TIMEOUT: `${ANSI.bYellow}⏱ TIMEOUT${ANSI.reset}`,
          CLEAN  : `${ANSI.bGreen}✓ CLEAN${ANSI.reset}`,
          ERROR  : `${ANSI.yellow}! ERROR${ANSI.reset}`,
          PENDING: `${ANSI.dim}… PENDING${ANSI.reset}`,
        };
        termWriteln(
          `${ANSI.dim}  result[${index}]  ` +
          `${icons[outcome]}  exit=${exitCode ?? "—"}  ` +
          `${ANSI.cyan}${payload.slice(0, 40)}${ANSI.reset}`
        );
        setResults(prev =>
          prev.map(r => r.index === index ? { ...r, outcome, exitCode } : r)
        );
        break;
      }

      case "done": {
        const summary = msg.summary as Record<string, unknown> | undefined;
        const counts  = (summary?.counts ?? {}) as Record<string, number>;
        termWriteln("");
        termWriteln(`${ANSI.green}${ANSI.bold}╔═══════════════════════════════════╗${ANSI.reset}`);
        termWriteln(`${ANSI.green}${ANSI.bold}║  FUZZING PIPELINE COMPLETE        ║${ANSI.reset}`);
        termWriteln(`${ANSI.green}${ANSI.bold}╚═══════════════════════════════════╝${ANSI.reset}`);
        Object.entries(counts).forEach(([k, v]) => {
          const col = k === "CRASH" ? ANSI.red : k === "TIMEOUT" ? ANSI.yellow : ANSI.green;
          termWriteln(`${ANSI.dim}  ${col}${k}${ANSI.reset}${ANSI.dim}: ${v}${ANSI.reset}`);
        });
        termWriteln("");
        setStatus("done");
        setStatusMsg("Pipeline complete.");
        wsRef.current?.close();
        break;
      }

      default:
        termWriteln(`${ANSI.dim}[unknown type: ${msg.type}]${ANSI.reset}`);
    }
  }, [termWrite, termWriteln]);

  // ── Launch ─────────────────────────────────────────────────────────────────
  const launch = useCallback(() => {
    if (!apiKey.trim()) {
      setStatusMsg("API key is required.");
      termWriteln(`${ANSI.bRed}✗ Please enter an API key before launching.${ANSI.reset}`);
      return;
    }

    wsRef.current?.close();

    termClear();
    setResults([]);
    setStatus("connecting");
    setStatusMsg("Connecting to backend…");

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    termWriteln(`${ANSI.dim}${ANSI.cyan}▶ Connecting to ${WS_URL}${ANSI.reset}`);
    termWriteln(`${ANSI.dim}  Provider : ${ANSI.magenta}${provider}${ANSI.reset}`);
    termWriteln(`${ANSI.dim}  Model    : ${ANSI.magenta}${modelId}${ANSI.reset}`);
    termWriteln(`${ANSI.dim}  API Key  : ${ANSI.magenta}${"•".repeat(Math.min(apiKey.length, 16))}${ANSI.reset}`);

    ws.onopen = () => {
      setStatus("compiling");
      setStatusMsg("Connected — sending source code…");
      termWriteln(`${ANSI.bGreen}✓ WebSocket open${ANSI.reset}`);
      ws.send(JSON.stringify({
        source_code: sourceCode,
        api_key    : apiKey,
        provider   : provider,
        model_id   : modelId,
      }));
    };

    ws.onmessage = (ev: MessageEvent<string>) => handleMessage(ev.data);

    ws.onerror = () => {
      termWriteln(`${ANSI.bRed}✗ WebSocket error — is the backend running?${ANSI.reset}`);
      setStatus("error");
      setStatusMsg("Connection error.");
    };

    ws.onclose = (ev: CloseEvent) => {
      termWriteln(`${ANSI.dim}WebSocket closed (code ${ev.code})${ANSI.reset}`);
      wsRef.current = null;
    };
  }, [apiKey, provider, modelId, sourceCode, handleMessage, termClear, termWriteln]);

  // Cleanup on unmount
  useEffect(() => () => { wsRef.current?.close(); }, []);

  // ── Derived ────────────────────────────────────────────────────────────────
  const isRunning    = ["connecting","compiling","generating","fuzzing"].includes(status);
  const crashCount   = results.filter(r => r.outcome === "CRASH").length;
  const cleanCount   = results.filter(r => r.outcome === "CLEAN").length;
  const timeoutCount = results.filter(r => r.outcome === "TIMEOUT").length;
  const apiKeyValid  = apiKey.trim().length > 0;

  // ── Status badge ───────────────────────────────────────────────────────────
  const StatusBadge: FC = () => {
    const map: Record<FuzzerStatus, { label: string; cls: string; spin?: boolean }> = {
      idle      : { label: "IDLE",       cls: "text-zinc-500  border-zinc-700"    },
      connecting: { label: "CONNECTING", cls: "text-blue-400  border-blue-700",   spin: true },
      compiling : { label: "COMPILING",  cls: "text-orange-400 border-orange-700", spin: true },
      generating: { label: "GENERATING", cls: "text-purple-400 border-purple-700", spin: true },
      fuzzing   : { label: "FUZZING",    cls: "text-emerald-400 border-emerald-700 animate-pulse" },
      done      : { label: "DONE",       cls: "text-emerald-400 border-emerald-700" },
      error     : { label: "ERROR",      cls: "text-red-400    border-red-700"    },
    };
    const s = map[status];
    return (
      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] font-mono tracking-widest ${s.cls}`}>
        {s.spin
          ? <Loader2 className="w-3 h-3 animate-spin" />
          : status === "fuzzing" ? <Zap className="w-3 h-3" />
          : status === "done"    ? <CircleCheck className="w-3 h-3" />
          : status === "error"   ? <CircleAlert className="w-3 h-3" />
          : <CircleDot className="w-3 h-3" />
        }
        {s.label}
      </span>
    );
  };

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div
      className="min-h-screen bg-[#07070d] text-zinc-300 flex flex-col"
      style={{ fontFamily: "'Rajdhani', 'Share Tech Mono', sans-serif" }}
    >
      {/* Scanline overlay */}
      <div
        className="pointer-events-none fixed inset-0 z-50 opacity-[0.03]"
        style={{ backgroundImage: "repeating-linear-gradient(0deg,transparent,transparent 2px,#000 2px,#000 4px)" }}
      />

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="border-b border-zinc-800/60 px-6 py-3 flex items-center justify-between bg-[#09090f]/80 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Bug className="w-5 h-5 text-emerald-400" />
            <div className="absolute -inset-1 bg-emerald-400/10 rounded-full blur-sm" />
          </div>
          <span
            className="text-lg font-bold tracking-[0.2em] text-emerald-300 uppercase"
            style={{ textShadow: "0 0 20px #39ff1440" }}
          >
            AI FUZZER
          </span>
          <span className="text-zinc-600 text-xs font-mono">v2.0 / byok</span>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <StatusBadge />
          <span className="text-zinc-500 max-w-xs truncate">{statusMsg}</span>
          {isRunning
            ? <Wifi    className="w-4 h-4 text-emerald-400 animate-pulse" />
            : <WifiOff className="w-4 h-4 text-zinc-600" />
          }
        </div>
      </header>

      {/* ── Body ───────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">

        {/* ══ LEFT PANEL ════════════════════════════════════════════════ */}
        <aside className="w-[400px] min-w-[340px] flex flex-col border-r border-zinc-800/60 bg-[#08080e]">

          {/* ── AI Configuration ──────────────────────────────────────── */}
          <div className="border-b border-zinc-800/40">
            <div className="px-4 py-2.5 flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-zinc-500" />
              <span className="text-xs font-mono tracking-widest text-zinc-400 uppercase">
                AI Configuration
              </span>
            </div>

            <div className="px-4 pb-4 space-y-3">

              {/* Provider + Model row */}
              <div className="grid grid-cols-2 gap-2">

                {/* Provider dropdown */}
                <div className="space-y-1">
                  <label className="block text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                    Provider
                  </label>
                  <div className="relative">
                    <select
                      value={provider}
                      onChange={handleProviderChange}
                      disabled={isRunning}
                      className={selectCls}
                    >
                      <option value="gemini">Gemini</option>
                      <option value="groq">Groq</option>
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-600" />
                  </div>
                </div>

                {/* Model dropdown — filtered by provider */}
                <div className="space-y-1">
                  <label className="block text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                    Model
                  </label>
                  <div className="relative">
                    <select
                      value={modelId}
                      onChange={e => setModelId(e.target.value)}
                      disabled={isRunning}
                      className={selectCls}
                    >
                      {PROVIDER_MODELS[provider].map(m => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-600" />
                  </div>
                </div>
              </div>

              {/* API Key input */}
              <div className="space-y-1">
                <label className="flex items-center gap-1.5 text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                  <KeyRound className="w-3 h-3" />
                  API Key
                  {apiKeyValid && (
                    <span className="ml-auto text-emerald-600 normal-case tracking-normal">
                      ✓ set
                    </span>
                  )}
                </label>
                <div className="relative">
                  <input
                    type={showApiKey ? "text" : "password"}
                    value={apiKey}
                    onChange={e => setApiKey(e.target.value)}
                    disabled={isRunning}
                    placeholder={provider === "gemini" ? "AIza…" : "gsk_…"}
                    className={`${inputCls} pr-8`}
                    autoComplete="off"
                    spellCheck={false}
                  />
                  <button
                    type="button"
                    onClick={() => setShowApiKey(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400 transition-colors"
                    tabIndex={-1}
                    aria-label={showApiKey ? "Hide API key" : "Show API key"}
                  >
                    {showApiKey
                      ? <EyeOff className="w-3.5 h-3.5" />
                      : <Eye    className="w-3.5 h-3.5" />
                    }
                  </button>
                </div>
                <p className="text-[9px] text-zinc-700 font-mono">
                  Sent once over WebSocket. Never logged or stored server-side.
                </p>
              </div>
            </div>
          </div>

          {/* ── Target Source ─────────────────────────────────────────── */}
          <div className="px-4 py-2.5 border-b border-zinc-800/40 flex items-center gap-2">
            <FlaskConical className="w-4 h-4 text-zinc-500" />
            <span className="text-xs font-mono tracking-widest text-zinc-400 uppercase">
              Target Source
            </span>
          </div>

          <div className="flex-1 p-3 overflow-hidden">
            <textarea
              className={`
                w-full h-full resize-none bg-[#050508] border border-zinc-800/60
                rounded text-[11px] leading-5 p-3
                text-emerald-100/80 placeholder-zinc-700
                focus:outline-none focus:border-emerald-800/60 focus:ring-1 focus:ring-emerald-900/40
                transition-colors duration-200
              `}
              style={{ fontFamily: "'Share Tech Mono', monospace" }}
              value={sourceCode}
              onChange={e => setSourceCode(e.target.value)}
              placeholder="Paste C++ source here…"
              spellCheck={false}
              disabled={isRunning}
            />
          </div>

          <div className="px-4 py-2 border-t border-zinc-800/40 flex gap-4 text-[10px] font-mono text-zinc-600">
            <span>{sourceCode.split("\n").length} lines</span>
            <span>{sourceCode.length} chars</span>
            <span className="ml-auto text-zinc-700">victim.cpp</span>
          </div>

          {/* ── Launch button ─────────────────────────────────────────── */}
          <div className="p-4 border-t border-zinc-800/40">
            <button
              onClick={launch}
              disabled={isRunning}
              className={`
                w-full relative overflow-hidden
                flex items-center justify-center gap-2.5
                py-3.5 px-6 rounded
                font-bold text-sm tracking-[0.2em] uppercase
                transition-all duration-200
                ${isRunning
                  ? "bg-zinc-800/40 text-zinc-600 cursor-not-allowed border border-zinc-700/40"
                  : !apiKeyValid
                    ? "bg-zinc-900/60 text-zinc-500 border border-zinc-800/40 cursor-not-allowed"
                    : "bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 hover:bg-emerald-900/60 hover:border-emerald-500/60 hover:shadow-[0_0_20px_rgba(57,255,20,0.15)] active:scale-[0.98]"
                }
              `}
              style={!isRunning && apiKeyValid ? { textShadow: "0 0 10px #39ff1460" } : {}}
              title={!apiKeyValid ? "Enter an API key to enable" : undefined}
            >
              {isRunning ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> FUZZING IN PROGRESS…</>
              ) : !apiKeyValid ? (
                <><KeyRound className="w-4 h-4 opacity-50" /> ENTER API KEY TO LAUNCH</>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  LAUNCH FUZZER
                  <ChevronRight className="w-3.5 h-3.5 opacity-60" />
                </>
              )}
            </button>
          </div>

          {/* ── Quick stats ───────────────────────────────────────────── */}
          {results.length > 0 && (
            <div className="px-4 pb-4 grid grid-cols-3 gap-2">
              {[
                { label: "CRASH",   count: crashCount,   cls: "text-red-400    border-red-900/60    bg-red-950/30"    },
                { label: "TIMEOUT", count: timeoutCount, cls: "text-yellow-400 border-yellow-900/60 bg-yellow-950/30" },
                { label: "CLEAN",   count: cleanCount,   cls: "text-emerald-400 border-emerald-900/60 bg-emerald-950/30" },
              ].map(s => (
                <div key={s.label} className={`border rounded p-2 text-center ${s.cls}`}>
                  <div className="text-xl font-bold font-mono">{s.count}</div>
                  <div className="text-[9px] tracking-widest opacity-70">{s.label}</div>
                </div>
              ))}
            </div>
          )}
        </aside>

        {/* ══ RIGHT PANEL ═══════════════════════════════════════════════ */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* ── Terminal ──────────────────────────────────────────────── */}
          <div className="flex flex-col" style={{ height: "60%" }}>
            <div className="px-4 py-2.5 border-b border-zinc-800/40 flex items-center gap-2 bg-[#08080e] flex-shrink-0">
              <Terminal className="w-3.5 h-3.5 text-zinc-500" />
              <span className="text-xs font-mono tracking-widest text-zinc-400 uppercase">
                Execution Log
              </span>
              {/* Active provider pill */}
              {(isRunning || status === "done") && (
                <span className="ml-2 px-1.5 py-0.5 rounded border border-purple-800/40 bg-purple-950/40 text-[10px] font-mono text-purple-400">
                  {provider} / {modelId}
                </span>
              )}
              <div className="ml-auto flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-red-600/60"    />
                <div className="w-2.5 h-2.5 rounded-full bg-yellow-600/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-600/60"/>
              </div>
            </div>
            <div ref={terminalDivRef} className="flex-1 overflow-hidden" style={{ background: "#0a0a0f" }} />
          </div>

          {/* ── Results table ─────────────────────────────────────────── */}
          <div className="flex flex-col border-t border-zinc-800/60" style={{ height: "40%" }}>
            <div className="px-4 py-2.5 border-b border-zinc-800/40 flex items-center gap-2 bg-[#08080e] flex-shrink-0">
              <Shield className="w-3.5 h-3.5 text-zinc-500" />
              <span className="text-xs font-mono tracking-widest text-zinc-400 uppercase">
                Fuzzing Results
              </span>
              {results.length > 0 && (
                <span className="ml-auto text-[10px] font-mono text-zinc-600">
                  {results.filter(r => r.outcome !== "PENDING").length}
                  &thinsp;/&thinsp;{results.length} complete
                </span>
              )}
            </div>

            <div className="flex-1 overflow-y-auto">
              {results.length === 0 ? (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center text-zinc-700">
                    <FlaskConical className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-xs font-mono tracking-widest uppercase">No results yet</p>
                  </div>
                </div>
              ) : (
                <table className="w-full text-xs font-mono border-collapse">
                  <thead className="sticky top-0 bg-[#08080e] z-10">
                    <tr className="text-[10px] tracking-widest text-zinc-600 uppercase">
                      <th className="text-left px-4 py-2 w-12 font-normal">#</th>
                      <th className="text-left px-4 py-2 w-28 font-normal">Status</th>
                      <th className="text-left px-4 py-2 w-24 font-normal">Exit</th>
                      <th className="text-left px-4 py-2 font-normal">Payload</th>
                    </tr>
                    <tr><td colSpan={4}><div className="h-px bg-zinc-800/60" /></td></tr>
                  </thead>
                  <tbody>
                    {results.map(r => (
                      <tr
                        key={r.index}
                        className={`border-b border-zinc-800/20 transition-colors duration-300 ${outcomeBg(r.outcome)}`}
                      >
                        <td className="px-4 py-2.5 text-zinc-600">{r.index}</td>
                        <td className="px-4 py-2.5">
                          <span className={`flex items-center gap-1.5 font-bold tracking-widest ${outcomeColor(r.outcome)}`}>
                            <OutcomeIcon outcome={r.outcome} />
                            {r.outcome}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-zinc-500">
                          {r.exitCode != null ? (
                            <span className={r.exitCode === 139 ? "text-red-400" : "text-zinc-400"}>
                              {r.exitCode}
                              {r.exitCode === 139 && (
                                <span className="ml-1.5 text-[9px] text-red-600">SIGSEGV</span>
                              )}
                            </span>
                          ) : (
                            <span className={r.outcome === "PENDING" ? "text-zinc-700 animate-pulse" : "text-zinc-700"}>—</span>
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="text-zinc-300 max-w-xs truncate block" title={r.payload}>
                            {r.payload.length > 70
                              ? `${r.payload.slice(0, 67)}…`
                              : r.payload || <span className="text-zinc-700 italic">(empty)</span>
                            }
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Footer ─────────────────────────────────────────────────────── */}
      <footer className="border-t border-zinc-800/40 px-6 py-2 flex items-center justify-between bg-[#07070d] text-[10px] font-mono text-zinc-700">
        <div className="flex items-center gap-4">
          <span>sandbox: seccomp-bpf + pivot_root + cgroups v2</span>
          <span className="text-zinc-800">│</span>
          <span className="text-zinc-600">{provider} / {modelId}</span>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-1.5 h-1.5 rounded-full ${isRunning ? "bg-emerald-400 animate-pulse" : "bg-zinc-700"}`} />
          {WS_URL}
        </div>
      </footer>
    </div>
  );
};

export default App;