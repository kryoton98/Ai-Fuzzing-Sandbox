/**
 * App.tsx — AI Fuzzer Dashboard  (v4: Freemium SaaS + Supabase Auth)
 * ════════════════════════════════════════════════════════════════════
 * Single-file React dashboard for the AI-driven fuzzing pipeline.
 *
 * What changed in v4
 * ──────────────────
 * · Supabase Auth: email/password login & signup overlay when unauthenticated.
 * · Provider dropdown now has three tiers:
 *     "gemini"  → Gemini (BYOK - Free)
 *     "groq"    → Groq (BYOK - Free)
 *     "premium" → Zero-Day Hacker Model (Pro ⚡)
 * · Conditional UI (Upsell):
 *     - BYOK providers: API Key input shown as normal.
 *     - "premium" selected: API Key input hidden.
 *     - "premium" + user is NOT pro: Launch button replaced with "Upgrade to Pro".
 * · WebSocket payload now includes `auth_token` (Supabase JWT access token).
 * · User avatar / logout button added to header.
 *
 * What was in v3 (unchanged)
 * ──────────────────────────
 * · Language selector (C++ / Python 3) with matching default source templates.
 * · xterm.js terminal with full ANSI colour rendering.
 * · Results table with outcome colouring and exit-code display.
 * · All existing seccomp/cgroup footer metadata.
 *
 * Stack requirements (package.json):
 *   react, react-dom, typescript
 *   tailwindcss
 *   @supabase/supabase-js
 *   @xterm/xterm  @xterm/addon-fit  @xterm/addon-web-links
 *   lucide-react
 *
 * Environment variables (Vite):
 *   VITE_SUPABASE_URL      — your Supabase project URL
 *   VITE_SUPABASE_ANON_KEY — your Supabase anon/public key
 *
 * CSS (index.css / globals.css) — add once:
 *   @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');
 *   @import '@xterm/xterm/css/xterm.css';
 */
import "@xterm/xterm/css/xterm.css";
import {
  useEffect,
  useRef,
  useState,
  useCallback,
  type FC,
  type ChangeEvent,
} from "react";
import { createClient, type SupabaseClient, type User } from "@supabase/supabase-js";
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
  Crown,
  Eye,
  EyeOff,
  FlaskConical,
  KeyRound,
  Loader2,
  LogOut,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  User as UserIcon,
  Wifi,
  WifiOff,
  Zap,
} from "lucide-react";

// ── Supabase Client ────────────────────────────────────────────────────────────

const supabase: SupabaseClient = createClient(
  import.meta.env.VITE_SUPABASE_URL  as string,
  import.meta.env.VITE_SUPABASE_ANON_KEY as string,
);

// ── Constants ──────────────────────────────────────────────────────────────────

const WS_URL = "ws://127.0.0.1:8000/ws/fuzz";

/** Provider → allowed models map (mirrors ALLOWED_MODELS in main.py) */
const PROVIDER_MODELS: Record<string, string[]> = {
  gemini : ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.5-pro"],
  groq   : ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
  premium: ["zero-day-v1"],
};

const DEFAULT_CPP = `#include <iostream>
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

/**
 * Default Python victim.
 * - "CRASH" → ZeroDivisionError (unhandled, exits non-zero)
 * - "LOOP"  → infinite while-loop (SIGKILL / timeout)
 * - else    → prints "Safe: <input>"
 */
const DEFAULT_PYTHON = `import sys

def main():
    try:
        data = input()
    except EOFError:
        print("[victim] stdin closed", file=sys.stderr)
        sys.exit(1)

    if data == "CRASH":
        print("[victim] CRASH -> triggering ZeroDivisionError", file=sys.stderr)
        # Deliberate unhandled exception — exits with code 1 and a traceback
        result = 1 / 0  # noqa: F841

    elif data == "LOOP":
        print("[victim] LOOP -> spinning forever", file=sys.stderr)
        while True:
            pass  # infinite spin — killed by sandbox timeout

    else:
        print(f"Safe: {data}")

if __name__ == "__main__":
    main()
`;

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

type Provider     = "gemini" | "groq" | "premium";
type Language     = "cpp" | "python";
type Outcome      = "CRASH" | "CLEAN" | "TIMEOUT" | "ERROR" | "PENDING";
type FuzzerStatus =
  | "idle" | "connecting" | "compiling"
  | "generating" | "fuzzing" | "done" | "error";
type AuthView     = "login" | "signup";

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

// ── Auth Overlay ───────────────────────────────────────────────────────────────

interface AuthOverlayProps {
  onAuth: (user: User) => void;
}

const AuthOverlay: FC<AuthOverlayProps> = ({ onAuth }) => {
  const [view,     setView    ] = useState<AuthView>("login");
  const [email,    setEmail   ] = useState("");
  const [password, setPassword] = useState("");
  const [showPw,   setShowPw  ] = useState(false);
  const [loading,  setLoading ] = useState(false);
  const [error,    setError   ] = useState<string | null>(null);
  const [info,     setInfo    ] = useState<string | null>(null);

  const handleSubmit = async () => {
    setError(null);
    setInfo(null);
    setLoading(true);

    try {
      if (view === "login") {
        const { data, error: e } = await supabase.auth.signInWithPassword({ email, password });
        if (e) throw e;
        if (data.user) onAuth(data.user);
      } else {
        const { data, error: e } = await supabase.auth.signUp({ email, password });
        if (e) throw e;
        if (data.user && data.session) {
          onAuth(data.user);
        } else {
          setInfo("Check your inbox to confirm your email, then log in.");
          setView("login");
        }
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Authentication failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    // Full-screen backdrop
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#07070d]/95 backdrop-blur-sm">
      {/* Scanline overlay (mirrored from main app) */}
      <div
        className="pointer-events-none fixed inset-0 z-0 opacity-[0.03]"
        style={{ backgroundImage: "repeating-linear-gradient(0deg,transparent,transparent 2px,#000 2px,#000 4px)" }}
      />

      <div className="relative z-10 w-full max-w-sm mx-4">
        {/* Glow halo */}
        <div className="absolute -inset-px rounded-lg bg-emerald-500/10 blur-xl pointer-events-none" />

        <div className="relative bg-[#09090f] border border-zinc-800/80 rounded-lg overflow-hidden">

          {/* Header */}
          <div className="px-6 pt-6 pb-4 border-b border-zinc-800/60 flex flex-col items-center gap-3">
            <div className="relative">
              <Bug className="w-7 h-7 text-emerald-400" />
              <div className="absolute -inset-2 bg-emerald-400/10 rounded-full blur-md" />
            </div>
            <div className="text-center">
              <h1
                className="text-xl font-bold tracking-[0.2em] text-emerald-300 uppercase"
                style={{ textShadow: "0 0 20px #39ff1440" }}
              >
                AI FUZZER
              </h1>
              <p className="text-[10px] font-mono text-zinc-600 mt-0.5 tracking-widest">
                {view === "login" ? "SIGN IN TO CONTINUE" : "CREATE YOUR ACCOUNT"}
              </p>
            </div>
          </div>

          {/* Form */}
          <div className="px-6 py-5 space-y-4">

            {/* Tab switcher */}
            <div className="grid grid-cols-2 gap-1 bg-zinc-900/60 rounded p-1">
              {(["login", "signup"] as AuthView[]).map(v => (
                <button
                  key={v}
                  onClick={() => { setView(v); setError(null); setInfo(null); }}
                  className={`
                    py-1.5 rounded text-[10px] font-mono tracking-widest uppercase transition-all duration-150
                    ${view === v
                      ? "bg-emerald-950/80 text-emerald-300 border border-emerald-800/60"
                      : "text-zinc-600 hover:text-zinc-400"}
                  `}
                >
                  {v === "login" ? "Log In" : "Sign Up"}
                </button>
              ))}
            </div>

            {/* Info / error banners */}
            {info && (
              <div className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 rounded px-3 py-2">
                {info}
              </div>
            )}
            {error && (
              <div className="text-[11px] font-mono text-red-400 bg-red-950/40 border border-red-800/40 rounded px-3 py-2">
                {error}
              </div>
            )}

            {/* Email */}
            <div className="space-y-1">
              <label className="block text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleSubmit()}
                placeholder="you@example.com"
                className={inputCls}
                autoComplete="email"
                disabled={loading}
              />
            </div>

            {/* Password */}
            <div className="space-y-1">
              <label className="block text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPw ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleSubmit()}
                  placeholder="••••••••"
                  className={`${inputCls} pr-8`}
                  autoComplete={view === "login" ? "current-password" : "new-password"}
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-400 transition-colors"
                  tabIndex={-1}
                >
                  {showPw ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {/* Submit */}
            <button
              onClick={handleSubmit}
              disabled={loading || !email || !password}
              className={`
                w-full relative overflow-hidden
                flex items-center justify-center gap-2
                py-3 px-6 rounded
                font-bold text-sm tracking-[0.2em] uppercase
                transition-all duration-200
                ${loading || !email || !password
                  ? "bg-zinc-800/40 text-zinc-600 cursor-not-allowed border border-zinc-700/40"
                  : "bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 hover:bg-emerald-900/60 hover:border-emerald-500/60 hover:shadow-[0_0_20px_rgba(57,255,20,0.15)] active:scale-[0.98]"
                }
              `}
              style={!loading && email && password ? { textShadow: "0 0 10px #39ff1460" } : {}}
            >
              {loading
                ? <><Loader2 className="w-4 h-4 animate-spin" /> AUTHENTICATING…</>
                : view === "login"
                  ? <><Zap className="w-4 h-4" /> LOG IN</>
                  : <><Sparkles className="w-4 h-4" /> CREATE ACCOUNT</>
              }
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ── Main Component ─────────────────────────────────────────────────────────────

const App: FC = () => {

  // ── Auth state ────────────────────────────────────────────────────────────
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Bootstrap: check for an existing session on mount, then subscribe to changes
  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setUser(data.session?.user ?? null);
      setAuthLoading(false);
    });

    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => listener.subscription.unsubscribe();
  }, []);

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    setUser(null);
  };

  // Derived: is this user a paying Pro member?
  const isPro: boolean = user?.user_metadata?.is_pro === true;

  // ── Refs ──────────────────────────────────────────────────────────────────
  const terminalDivRef = useRef<HTMLDivElement>(null);
  const xtermRef       = useRef<XTerm | null>(null);
  const fitAddonRef    = useRef<FitAddon | null>(null);
  const wsRef          = useRef<WebSocket | null>(null);
  const roRef          = useRef<ResizeObserver | null>(null);

  // ── Core fuzzer state ─────────────────────────────────────────────────────
  const [sourceCode, setSourceCode] = useState<string>(DEFAULT_CPP);
  const [language,   setLanguage  ] = useState<Language>("cpp");
  const [status,     setStatus    ] = useState<FuzzerStatus>("idle");
  const [results,    setResults   ] = useState<FuzzResult[]>([]);
  const [statusMsg,  setStatusMsg ] = useState<string>("Ready to fuzz.");

  // ── AI Configuration state ────────────────────────────────────────────────
  const [provider,   setProvider  ] = useState<Provider>("gemini");
  const [modelId,    setModelId   ] = useState<string>(PROVIDER_MODELS.gemini[0]);
  const [apiKey,     setApiKey    ] = useState<string>("");
  const [showApiKey, setShowApiKey] = useState<boolean>(false);

  // Derived: "premium" tier is selected
  const isPremiumSelected = provider === "premium";
  // Derived: BYOK tiers need a valid API key; premium does not
  const apiKeyValid = isPremiumSelected || apiKey.trim().length > 0;

  // When the provider changes, reset modelId to the first model of that provider
  const handleProviderChange = useCallback((e: ChangeEvent<HTMLSelectElement>) => {
    const p = e.target.value as Provider;
    setProvider(p);
    setModelId(PROVIDER_MODELS[p][0]);
  }, []);

  // When the language changes, load the matching default source template.
  const handleLanguageChange = useCallback((e: ChangeEvent<HTMLSelectElement>) => {
    const lang = e.target.value as Language;
    setLanguage(lang);
    setSourceCode(lang === "python" ? DEFAULT_PYTHON : DEFAULT_CPP);
  }, []);

  // ── xterm initialisation ──────────────────────────────────────────────────
  // NOTE: authLoading is in the dependency array intentionally.
  // When authLoading is true the component returns the loading spinner early,
  // so terminalDivRef.current is null and the effect bails out immediately.
  // Once authLoading flips to false the main layout renders, the div mounts,
  // and this effect re-runs — this time finding a real DOM node to attach to.
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

    // Two-phase fit:
    // · Immediate call handles the common case where layout is already settled.
    // · rAF call is the safety net: flex containers with percentage heights may
    //   not have their final pixel dimensions until after the first browser paint.
    //   Without this, xterm measures 0px on the first render and shows nothing.
    fit.fit();
    const rafId = requestAnimationFrame(() => fit.fit());

    xtermRef.current    = term;
    fitAddonRef.current = fit;

    term.writeln(`${ANSI.dim}${ANSI.green}┌──────────────────────────────────────────────┐${ANSI.reset}`);
    term.writeln(`${ANSI.green}  AI FUZZER TERMINAL  ${ANSI.dim}v4.0  · SaaS${ANSI.reset}`);
    term.writeln(`${ANSI.dim}${ANSI.green}└──────────────────────────────────────────────┘${ANSI.reset}`);
    term.writeln(`${ANSI.dim}Select a provider, configure your target, and launch.${ANSI.reset}`);

    const ro = new ResizeObserver(() => fit.fit());
    ro.observe(terminalDivRef.current);
    roRef.current = ro;

    return () => {
      cancelAnimationFrame(rafId);
      ro.disconnect();
      term.dispose();
      xtermRef.current    = null;
      fitAddonRef.current = null;
    };
  }, [authLoading]);
  const termWriteln = useCallback((line: string) => {
    xtermRef.current?.writeln(line);
  }, []);
  const termWrite   = useCallback((text: string) => {
    xtermRef.current?.write(text);
  }, []);
  const termClear   = useCallback(() => {
    xtermRef.current?.clear();
  }, []);

  // ── WebSocket message handler ─────────────────────────────────────────────
  const handleMessage = useCallback((raw: string) => {
    let msg: Record<string, unknown>;
    try { msg = JSON.parse(raw); }
    catch { termWriteln(`${ANSI.dim}[raw] ${raw}${ANSI.reset}`); return; }

    switch (msg.type) {

      case "info": {
        const text = String(msg.message ?? "");
        termWriteln(`${ANSI.dim}${ANSI.blue}ℹ ${ANSI.reset}${ANSI.dim}${text}${ANSI.reset}`);
        setStatusMsg(text.slice(0, 120));
        if (/stage 1|compil/i.test(text))                    setStatus("compiling");
        else if (/stage 2|gemini|groq|generat/i.test(text))  setStatus("generating");
        else if (/stage 3|sandbox|execut/i.test(text))       setStatus("fuzzing");
        else if (/pipeline complete/i.test(text))            setStatus("done");
        else if (/error/i.test(text))                        setStatus("error");
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

  // ── Launch ────────────────────────────────────────────────────────────────
  const launch = useCallback(async () => {
    // Gate: BYOK providers still need a key
    if (!isPremiumSelected && !apiKey.trim()) {
      setStatusMsg("API key is required.");
      termWriteln(`${ANSI.bRed}✗ Please enter an API key before launching.${ANSI.reset}`);
      return;
    }

    // Retrieve the current JWT access token from Supabase
    const { data: sessionData } = await supabase.auth.getSession();
    const authToken = sessionData?.session?.access_token ?? "";

    wsRef.current?.close();

    termClear();
    setResults([]);
    setStatus("connecting");
    setStatusMsg("Connecting to backend…");

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    termWriteln(`${ANSI.dim}${ANSI.cyan}▶ Connecting to ${WS_URL}${ANSI.reset}`);
    termWriteln(`${ANSI.dim}  Language : ${ANSI.magenta}${language === "python" ? "Python 3" : "C++ (g++)"}${ANSI.reset}`);
    termWriteln(`${ANSI.dim}  Provider : ${ANSI.magenta}${provider}${ANSI.reset}`);
    termWriteln(`${ANSI.dim}  Model    : ${ANSI.magenta}${modelId}${ANSI.reset}`);
    if (!isPremiumSelected) {
      termWriteln(`${ANSI.dim}  API Key  : ${ANSI.magenta}${"•".repeat(Math.min(apiKey.length, 16))}${ANSI.reset}`);
    }
    termWriteln(`${ANSI.dim}  Auth     : ${ANSI.magenta}JWT ${authToken ? "present" : "missing"}${ANSI.reset}`);

    ws.onopen = () => {
      setStatus("compiling");
      setStatusMsg("Connected — sending source code…");
      termWriteln(`${ANSI.bGreen}✓ WebSocket open${ANSI.reset}`);
      ws.send(JSON.stringify({
        source_code: sourceCode,
        api_key    : isPremiumSelected ? "" : apiKey,
        provider   : provider,
        model_id   : modelId,
        language   : language,
        auth_token : authToken,      // ← Supabase JWT
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
  }, [
    apiKey, isPremiumSelected, language, provider, modelId,
    sourceCode, handleMessage, termClear, termWriteln,
  ]);

  // Cleanup on unmount
  useEffect(() => () => { wsRef.current?.close(); }, []);

  // ── Derived ───────────────────────────────────────────────────────────────
  const isRunning    = ["connecting","compiling","generating","fuzzing"].includes(status);
  const crashCount   = results.filter(r => r.outcome === "CRASH").length;
  const cleanCount   = results.filter(r => r.outcome === "CLEAN").length;
  const timeoutCount = results.filter(r => r.outcome === "TIMEOUT").length;

  // "Upgrade to Pro" scenario: user picked premium but account isn't pro
  const showUpgradeButton = isPremiumSelected && !isPro;
  // Launch is disabled when: running, or premium+not-pro, or missing API key
  const launchDisabled    = isRunning || showUpgradeButton || !apiKeyValid;

  // ── Status badge ──────────────────────────────────────────────────────────
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
          : status === "fuzzing" ? <Zap        className="w-3 h-3" />
          : status === "done"    ? <CircleCheck className="w-3 h-3" />
          : status === "error"   ? <CircleAlert className="w-3 h-3" />
          :                        <CircleDot   className="w-3 h-3" />
        }
        {s.label}
      </span>
    );
  };

  // ── Render ────────────────────────────────────────────────────────────────

  // While Supabase resolves the existing session, show a minimal loader
  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#07070d] flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-emerald-500 animate-spin" />
      </div>
    );
  }

  return (
    <div
      className="h-screen bg-[#07070d] text-zinc-300 flex flex-col overflow-hidden"
      style={{ fontFamily: "'Rajdhani', 'Share Tech Mono', sans-serif" }}
    >
      {/* Scanline overlay */}
      <div
        className="pointer-events-none fixed inset-0 z-50 opacity-[0.03]"
        style={{ backgroundImage: "repeating-linear-gradient(0deg,transparent,transparent 2px,#000 2px,#000 4px)" }}
      />

      {/* ── Auth Overlay — rendered on top when logged out ─────────────────── */}
      {!user && <AuthOverlay onAuth={setUser} />}

      {/* ── Header ─────────────────────────────────────────────────────────── */}
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
          <span className="text-zinc-600 text-xs font-mono">v4.0 / saas</span>
          {/* Pro badge */}
          {isPro && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-amber-700/60 bg-amber-950/40 text-[9px] font-mono text-amber-400 tracking-widest">
              <Crown className="w-2.5 h-2.5" /> PRO
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <StatusBadge />
          <span className="text-zinc-500 max-w-xs truncate">{statusMsg}</span>
          {isRunning
            ? <Wifi    className="w-4 h-4 text-emerald-400 animate-pulse" />
            : <WifiOff className="w-4 h-4 text-zinc-600" />
          }

          {/* User avatar + sign-out */}
          {user && (
            <div className="flex items-center gap-2 ml-2 pl-3 border-l border-zinc-800">
              <UserIcon className="w-3.5 h-3.5 text-zinc-500" />
              <span className="text-zinc-500 text-[10px] max-w-[140px] truncate">
                {user.email}
              </span>
              <button
                onClick={handleSignOut}
                title="Sign out"
                className="p-1 rounded text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800/60 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </header>

      {/* ── Body ─────────────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">

        {/* ══ LEFT PANEL ══════════════════════════════════════════════════════ */}
        <aside className="w-[400px] min-w-[340px] flex flex-col border-r border-zinc-800/60 bg-[#08080e]">

          {/* ── AI Configuration ────────────────────────────────────────────── */}
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
                      <option value="gemini">Gemini (BYOK - Free)</option>
                      <option value="groq">Groq (BYOK - Free)</option>
                      <option value="premium">Zero-Day Hacker Model (Pro ⚡)</option>
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-600" />
                  </div>
                </div>

                {/* Model dropdown — filtered by provider; hidden for premium */}
                <div className="space-y-1">
                  <label className="block text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                    Model
                  </label>
                  <div className="relative">
                    <select
                      value={modelId}
                      onChange={e => setModelId(e.target.value)}
                      disabled={isRunning || isPremiumSelected}
                      className={selectCls}
                    >
                      {isPremiumSelected ? (
                        <option value="zero-day-v1">zero-day-v1</option>
                      ) : (
                        PROVIDER_MODELS[provider].map(m => (
                          <option key={m} value={m}>{m}</option>
                        ))
                      )}
                    </select>
                    <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-600" />
                  </div>
                </div>
              </div>

              {/* API Key input — hidden for premium tier */}
              {!isPremiumSelected && (
                <div className="space-y-1">
                  <label className="flex items-center gap-1.5 text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                    <KeyRound className="w-3 h-3" />
                    API Key
                    {apiKey.trim().length > 0 && (
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
              )}

              {/* Premium tier info pill */}
              {isPremiumSelected && (
                <div className={`
                  rounded border px-3 py-2.5 text-[11px] font-mono space-y-1
                  ${isPro
                    ? "bg-amber-950/30 border-amber-800/40 text-amber-400"
                    : "bg-zinc-900/60  border-zinc-700/40  text-zinc-500"}
                `}>
                  {isPro ? (
                    <p className="flex items-center gap-1.5">
                      <Crown className="w-3 h-3" />
                      Pro model active — no API key required.
                    </p>
                  ) : (
                    <>
                      <p className="flex items-center gap-1.5 text-zinc-400">
                        <Crown className="w-3 h-3 text-amber-600" />
                        Pro plan required for this model.
                      </p>
                      <p className="text-zinc-600 text-[10px]">
                        Upgrade to unlock the Zero-Day Hacker Model and remove the BYOK requirement.
                      </p>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* ── Language Selection ───────────────────────────────────────────── */}
          <div className="border-b border-zinc-800/40">
            <div className="px-4 py-2.5 flex items-center gap-2">
              <CircleDot className="w-3.5 h-3.5 text-zinc-500" />
              <span className="text-xs font-mono tracking-widest text-zinc-400 uppercase">
                Language
              </span>
            </div>

            <div className="px-4 pb-4">
              <div className="space-y-1">
                <label className="block text-[10px] font-mono tracking-widest text-zinc-600 uppercase">
                  Target Language
                </label>
                <div className="relative">
                  <select
                    value={language}
                    onChange={handleLanguageChange}
                    disabled={isRunning}
                    className={selectCls}
                  >
                    <option value="cpp">C++ (g++)</option>
                    <option value="python">Python 3</option>
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-600" />
                </div>
                <p className="text-[9px] text-zinc-700 font-mono">
                  {language === "python"
                    ? "Executed via: python3 victim.py"
                    : "Compiled via: g++ -std=c++17 -O0"}
                </p>
              </div>
            </div>
          </div>

          {/* ── Target Source ────────────────────────────────────────────────── */}
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
              placeholder={language === "python" ? "Paste Python source here…" : "Paste C++ source here…"}
              spellCheck={false}
              disabled={isRunning}
            />
          </div>

          <div className="px-4 py-2 border-t border-zinc-800/40 flex gap-4 text-[10px] font-mono text-zinc-600">
            <span>{sourceCode.split("\n").length} lines</span>
            <span>{sourceCode.length} chars</span>
            <span className="ml-auto text-zinc-700">{language === "python" ? "victim.py" : "victim.cpp"}</span>
          </div>

          {/* ── Launch / Upgrade button ──────────────────────────────────────── */}
          <div className="p-4 border-t border-zinc-800/40">
            {showUpgradeButton ? (
              /* ── Upgrade to Pro CTA ──────────────────────────────────────── */
              <button
                onClick={() => {
                  // TODO: wire to your billing / Stripe checkout URL
                  window.open("https://yourapp.com/upgrade", "_blank");
                }}
                className="
                  w-full relative overflow-hidden
                  flex items-center justify-center gap-2.5
                  py-3.5 px-6 rounded
                  font-bold text-sm tracking-[0.2em] uppercase
                  transition-all duration-200
                  bg-amber-950/80 text-amber-300
                  border border-amber-700/60
                  hover:bg-amber-900/60 hover:border-amber-500/60
                  hover:shadow-[0_0_24px_rgba(251,191,36,0.2)]
                  active:scale-[0.98]
                "
                style={{ textShadow: "0 0 10px rgba(251,191,36,0.4)" }}
              >
                {/* Animated shimmer sweep */}
                <span
                  className="pointer-events-none absolute inset-0 -translate-x-full animate-[shimmer_2s_ease-in-out_infinite]"
                  style={{
                    background: "linear-gradient(90deg, transparent 0%, rgba(251,191,36,0.08) 50%, transparent 100%)",
                    animation: "shimmer 2.2s ease-in-out infinite",
                  }}
                />
                <Crown className="w-4 h-4 text-amber-400" />
                UPGRADE TO PRO
                <ChevronRight className="w-3.5 h-3.5 opacity-60" />
              </button>
            ) : (
              /* ── Normal Launch button ────────────────────────────────────── */
              <button
                onClick={launch}
                disabled={launchDisabled}
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
                style={!launchDisabled && apiKeyValid ? { textShadow: "0 0 10px #39ff1460" } : {}}
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
            )}
          </div>

          {/* ── Quick stats ──────────────────────────────────────────────────── */}
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

        {/* ══ RIGHT PANEL ═════════════════════════════════════════════════════ */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* ── Terminal ──────────────────────────────────────────────────────── */}
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
            <div ref={terminalDivRef} className="flex-1 overflow-hidden" style={{ background: "#0a0a0f", minHeight: 0 }} />
          </div>

          {/* ── Results table ─────────────────────────────────────────────────── */}
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

      {/* ── Footer ───────────────────────────────────────────────────────────── */}
      <footer className="border-t border-zinc-800/40 px-6 py-2 flex items-center justify-between bg-[#07070d] text-[10px] font-mono text-zinc-700">
        <div className="flex items-center gap-4">
          <span>sandbox: seccomp-bpf + pivot_root + cgroups v2</span>
          <span className="text-zinc-800">│</span>
          <span className="text-zinc-600">{language === "python" ? "python3" : "g++ -std=c++17"}</span>
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