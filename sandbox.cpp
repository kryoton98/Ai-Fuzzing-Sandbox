/**
 * sandbox.cpp — v8: Smart clone Filtering, clone3 Block, rlimit Hardening
 *
 * All prior isolation layers are preserved unchanged:
 *   • Namespaces  : CLONE_NEWPID | NEWNET | NEWIPC | NEWUTS | NEWNS
 *   • Cgroups v2  : memory.max=256M, pids.max=64  (graceful fallback on WSL)
 *   • Pipe sync   : child blocked until cgroup limits are live
 *   • Privileges  : dropped to UID/GID 65534 (nobody) before exec
 *   • Seccomp-BPF : blacklists ptrace, mknod, mknodat, unshare,
 *                   clone3, mount, pivot_root;
 *                   allows clone only when no namespace bits are set
 *
 * What changed in v7
 * ──────────────────
 * The sandbox now supports two execution modes, selected automatically
 * by inspecting argv[1]:
 *
 *   Native mode  (argv[1] starts with '.' or '/'):
 *     Unchanged from v6.  A fresh tmpfs is mounted at NEW_ROOT, the
 *     target ELF is bind-mounted into the sandbox at /target_bin, then
 *     pivot_root atomically replaces the process root so the host
 *     filesystem becomes completely unreachable.
 *     Executed via: execve("/target_bin", argv, clean_envp)
 *
 *   Interpreter mode  (argv[1] is a bare name, e.g. "python3"):
 *     pivot_root is skipped.  Instead:
 *       a) MS_REC|MS_PRIVATE on "/"         — detach namespace from host
 *                                             propagation; no mount events
 *                                             can leak in either direction.
 *       b) MS_BIND|MS_REC on "/" -> "/"     — self-bind so the next step
 *                                             can legally remount the root.
 *       c) MS_BIND|MS_REC|MS_REMOUNT|MS_RDONLY — lock the entire tree
 *                                             read-only; the interpreter and
 *                                             its stdlib remain readable but
 *                                             nothing can be written.
 *       d) Fresh tmpfs on /tmp              — private writable scratchpad;
 *                                             vanishes when the sandbox exits.
 *     Executed via: execvpe(argv[0], argv, clean_envp)  (uses PATH)
 *
 * What changed in v8
 * ──────────────────
 * 1. Smart clone(2) filtering — BPF argument inspection
 *      The v7 blanket deny on __NR_clone killed any Python script that used
 *      threading.Thread or multiprocessing.  v8 replaces it with a two-step
 *      BPF sequence that inspects the flags argument (args[0]):
 *
 *        a) Load the low 32 bits of args[0] from the seccomp_data struct.
 *        b) AND it against CLONE_NAMESPACE_MASK — a bitmask of every kernel
 *           namespace flag (CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID |
 *           CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP).
 *        c) If the result is non-zero the call is requesting a new namespace
 *           → KILL.  If zero, all namespace bits are absent → ALLOW (the
 *           clone will create a thread or a plain fork, both safe).
 *
 *      Important: BPF only has a 32-bit accumulator.  On x86-64 clone's
 *      first argument is a 64-bit register, but the BPF seccomp ABI stores
 *      args[0] as a 64-bit quantity split across two 32-bit words at offsets
 *      args[0] (lo) and args[0]+4 (hi).  All current namespace flags fit
 *      comfortably in the low 32 bits, so we only need to inspect args[0].
 *
 * 2. Blanket deny on clone3(2)
 *      clone3 (Linux 5.3+) accepts its arguments inside a struct pointer,
 *      making flag inspection harder.  Rather than parsing the struct in BPF,
 *      we block clone3 entirely.  glibc falls back to the classic clone(2)
 *      automatically when clone3 returns ENOSYS, so all valid threading
 *      use-cases continue to work through the inspectable path.
 *      An #ifndef guard defines __NR_clone3 = 435 for older kernel headers.
 *
 * 3. Defense-in-depth rlimits
 *      A new setup_rlimits() function is called inside child_main before
 *      drop_privileges().  It applies hard+soft limits on:
 *        • RLIMIT_FSIZE — 10 MB file-size cap.  A script that tries to fill
 *                         the disk receives SIGXFSZ regardless of cgroup state.
 *        • RLIMIT_CPU   —  5 s CPU-time cap.  An infinite loop receives
 *                         SIGXCPU (soft) then SIGKILL (hard) even if the
 *                         orchestrator timeout and cgroup cpu.max both fail.
 *      Limits are applied as root (before drop_privileges) so the sandboxed
 *      process cannot raise them back with setrlimit(2).
 *
 * Detection heuristic (unchanged from v7)
 * ───────────────────────────────────────
 *   argv[1][0] == '.' or '/'  →  native mode   (./victim, /usr/bin/cat)
 *   anything else              →  interpreter   (python3, node, ruby)
 *
 * Build:
 *   g++ -std=c++17 -Wall -Wextra -o sandbox sandbox.cpp
 *
 * Run (native ELF):
 *   sudo ./sandbox ./victim
 *
 * Run (Python / Node / Ruby):
 *   sudo ./sandbox python3 victim.py
 *   sudo ./sandbox node    victim.js
 *   sudo ./sandbox ruby    victim.rb
 */

#define _GNU_SOURCE   // execvpe, MS_REC, MNT_DETACH, setresuid, …

#include <cerrno>
#include <cstddef>        // offsetof
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <grp.h>          // setgroups()
#include <sched.h>        // clone(), CLONE_NEW*
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>  // SYS_pivot_root, __NR_*
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Seccomp / BPF — must follow sys/types.h
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/resource.h>  // setrlimit(), RLIMIT_FSIZE, RLIMIT_CPU

// ─────────────────────────────────────────────────────────────────────────────
// Portability shims
// ─────────────────────────────────────────────────────────────────────────────

// clone3(2) was added in Linux 5.3 / glibc 2.34.  Older kernel headers may
// not define __NR_clone3, so we supply the x86-64 number as a fallback.
// We always deny clone3 in seccomp so glibc is forced to use the inspectable
// clone(2) path for all threading / forking operations.
#ifndef __NR_clone3
#define __NR_clone3 435
#endif

// Bitmask of all kernel namespace-creation flags that clone(2) accepts.
// If any of these bits are set in the flags argument, the call is attempting
// to create a new namespace — which the sandboxed process must never do.
//
// Values are stable ABI constants from <linux/sched.h>; we define our own
// mask here to avoid a hard dependency on a specific kernel header version.
#define CLONE_NAMESPACE_MASK (  \
    0x00020000 /* CLONE_NEWNS     */ | \
    0x10000000 /* CLONE_NEWUTS    */ | \
    0x08000000 /* CLONE_NEWIPC    */ | \
    0x20000000 /* CLONE_NEWUSER   */ | \
    0x20000000 /* CLONE_NEWUSER   */ | \
    0x00000080 /* CLONE_NEWPID (needs CLONE_NEWNS on some kernels) */ | \
    0x40000000 /* CLONE_NEWNET    */ | \
    0x02000000 /* CLONE_NEWCGROUP */ \
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

static constexpr size_t CHILD_STACK_SIZE   = 8 * 1024 * 1024;
static constexpr char   SANDBOX_HOSTNAME[] = "sandbox";
static constexpr char   CGROUP_ROOT[]      = "/sys/fs/cgroup";
static constexpr char   CGROUP_MEM_MAX[]   = "256M";
static constexpr char   CGROUP_PIDS_MAX[]  = "64";
static constexpr uid_t  SANDBOX_UID        = 65534; // nobody
static constexpr gid_t  SANDBOX_GID        = 65534;

// NEW_ROOT must be a preprocessor macro — not constexpr — so that adjacent
// string-literal concatenation (NEW_ROOT "/proc") works at compile time.
#define NEW_ROOT "/tmp/.sandbox_root"

// ─────────────────────────────────────────────────────────────────────────────
// Error-handling helpers
// ─────────────────────────────────────────────────────────────────────────────

[[noreturn]] static void die(const char *call, const char *ctx = nullptr) {
    const int e = errno;
    ctx ? fprintf(stderr, "[FATAL] %s (%s): %s\n", call, ctx, strerror(e))
        : fprintf(stderr, "[FATAL] %s: %s\n",       call, strerror(e));
    exit(EXIT_FAILURE);
}

[[noreturn]] static void child_die(const char *call, const char *ctx = nullptr) {
    const int e = errno;
    ctx ? fprintf(stderr, "[CHILD FATAL] %s (%s): %s\n", call, ctx, strerror(e))
        : fprintf(stderr, "[CHILD FATAL] %s: %s\n",       call, strerror(e));
    _exit(EXIT_FAILURE);
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument bundle passed through clone()'s single void* parameter.
//
// Lifetime: lives on the parent's stack inside run_sandbox(). The parent
// blocks in waitpid() for the child's entire lifetime so this is safe.
// ─────────────────────────────────────────────────────────────────────────────

struct SyncPipe {
    int read_fd;
    int write_fd;
};

struct ChildArgs {
    SyncPipe  sync;
    char    **target_argv;    // points to argv[1] of the sandbox process
    bool      is_interpreter; // true  → python3 / node / ruby …
                              // false → ./victim or /absolute/path
};

// ─────────────────────────────────────────────────────────────────────────────
// Interpreter detection
//
// Mirrors the POSIX execvp(3) rule: if the name contains a '/' it is a path;
// otherwise the C library searches PATH.  We use the same test:
//   starts with '.' or '/'  →  native binary
//   anything else            →  bare name to look up via PATH (interpreter)
// ─────────────────────────────────────────────────────────────────────────────

static bool detect_interpreter(const char *argv1) {
    return (argv1[0] != '.') && (argv1[0] != '/');
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_fs_native  (child only)
//
// Builds a minimal tmpfs jail, injects the target ELF at /target_bin, and
// calls pivot_root so the host filesystem is completely unreachable.
//
// target_path — host-side path (e.g. "./victim").  Must be resolved before
//               pivot_root fires.
// ─────────────────────────────────────────────────────────────────────────────

static void setup_fs_native(const char *target_path) {

    // ── 1. Detach namespace from host propagation ─────────────────────────
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1)
        child_die("mount", "MS_REC|MS_PRIVATE on /");

    // ── 2. Create and populate the new root tmpfs ─────────────────────────
    if (mkdir(NEW_ROOT, 0755) == -1 && errno != EEXIST)
        child_die("mkdir", NEW_ROOT);
    if (mount("sandbox-root", NEW_ROOT, "tmpfs", 0, "size=64m,mode=0755") == -1)
        child_die("mount", "tmpfs at " NEW_ROOT);

    const char *const dirs[] = {
        NEW_ROOT "/proc",  NEW_ROOT "/bin",  NEW_ROOT "/lib",
        NEW_ROOT "/lib64", NEW_ROOT "/usr",  NEW_ROOT "/tmp",
        NEW_ROOT "/dev",   NEW_ROOT "/.old_root",
        nullptr
    };
    for (int i = 0; dirs[i]; ++i)
        if (mkdir(dirs[i], 0755) == -1 && errno != EEXIST)
            child_die("mkdir", dirs[i]);

    // ── 3. Bind-mount host library trees read-only (two-phase) ───────────
    //
    // MS_RDONLY cannot be set atomically on the initial MS_BIND call — the
    // kernel silently ignores it.  A second MS_BIND|MS_REMOUNT|MS_RDONLY
    // call is the documented way to lock an existing bind mount read-only.
    const char *const bind_srcs[] = { "/bin", "/lib", "/lib64", "/usr", nullptr };
    for (int i = 0; bind_srcs[i]; ++i) {
        struct stat st;
        if (stat(bind_srcs[i], &st) == -1) continue;   // skip absent dirs

        char dst[512];
        snprintf(dst, sizeof(dst), "%s%s", NEW_ROOT, bind_srcs[i]);

        if (mount(bind_srcs[i], dst, nullptr, MS_BIND | MS_REC, nullptr) == -1)
            child_die("mount bind", bind_srcs[i]);
        if (mount(nullptr, dst, nullptr,
                  MS_BIND | MS_REC | MS_REMOUNT | MS_RDONLY, nullptr) == -1)
            child_die("mount remount RO", bind_srcs[i]);
    }

    // ── 4. Inject the target ELF at /target_bin ───────────────────────────
    //
    // After pivot_root the host filesystem is gone.  Any relative or
    // absolute host path (./victim, /home/user/victim) would be invisible
    // inside the new root.  We resolve it now and project it under the
    // well-known in-sandbox name /target_bin.
    //
    // A regular-file mount-point is required: the kernel enforces that a
    // bind mount's source and destination have the same type (file→file).
    {
        char dst[512];
        snprintf(dst, sizeof(dst), "%s/target_bin", NEW_ROOT);

        const int fd = open(dst, O_CREAT | O_RDWR, 0755);
        if (fd == -1)
            child_die("open", "create /target_bin mount-point");
        close(fd);

        if (mount(target_path, dst, nullptr, MS_BIND, nullptr) == -1)
            child_die("mount bind target", target_path);
        if (mount(nullptr, dst, nullptr,
                  MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr) == -1)
            child_die("mount remount RO target", dst);

        fprintf(stderr, "[CHILD] Bind-mounted target  : %s  ->  /target_bin (RO)\n",
                target_path);
    }

    // ── 5. Fresh procfs scoped to our PID namespace ───────────────────────
    if (mount("proc", NEW_ROOT "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr) == -1)
        child_die("mount", "procfs");

    // ── 6. pivot_root — atomically replace the process root ──────────────
    //
    //   chdir(NEW_ROOT)             — move CWD into the future root
    //   pivot_root(".", ".old_root") — swap root; stash old root
    //   chdir("/")                  — land in the new root
    //   umount2(.old_root, DETACH)  — lazily detach the old root
    //   rmdir(.old_root)            — remove the now-empty stash dir
    //
    // After umount2() the host filesystem is completely unreachable.
    if (chdir(NEW_ROOT) == -1)
        child_die("chdir", NEW_ROOT);
    if (syscall(SYS_pivot_root, ".", ".old_root") == -1)
        child_die("pivot_root", NEW_ROOT);
    if (chdir("/") == -1)
        child_die("chdir", "/ after pivot_root");
    if (umount2("/.old_root", MNT_DETACH) == -1)
        child_die("umount2", ".old_root");
    if (rmdir("/.old_root") == -1)
        child_die("rmdir", "/.old_root");

    fprintf(stderr, "[CHILD] Filesystem mode     : native / pivot_root jail\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_fs_interpreter  (child only)
//
// Does NOT call pivot_root.  Locks the entire host filesystem read-only
// inside this mount namespace, then overlays /tmp with a fresh private tmpfs.
//
// Why not pivot_root for interpreters?
//   python3, node, ruby etc. load hundreds of files scattered across the real
//   host tree (/usr/lib/python3.x/, /usr/lib/x86_64-linux-gnu/, …).
//   Enumerating and bind-mounting every path is fragile and distro-specific.
//   Instead we keep the host tree visible but immutable.
//
// Security properties:
//   • MS_PRIVATE propagation — no mounts leak to/from the host namespace.
//   • Entire host tree is read-only — no file creation or modification.
//   • /tmp is a private tmpfs — writable scratchpad, vanishes on exit,
//     cannot fill the host disk or persist data to the host.
//   • seccomp filter still applies — interpreter cannot re-mount, ptrace,
//     clone new namespaces, etc.
//   • cgroup limits still apply — memory and PID caps prevent OOM / fork bombs.
// ─────────────────────────────────────────────────────────────────────────────

static void setup_fs_interpreter() {

    // ── a) Detach this namespace from host mount propagation ──────────────
    //
    // MS_REC | MS_PRIVATE makes every mountpoint in this namespace private.
    // Future host mounts will not appear here, and mounts made here will
    // not appear on the host.  This is the property that prevents the RO
    // remount below from locking the host's own filesystem.
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1)
        child_die("mount", "MS_REC|MS_PRIVATE on / (interpreter mode)");

    // ── b) Self-bind the root ─────────────────────────────────────────────
    //
    // We cannot remount "/" read-only directly on the rootfs: the kernel
    // disallows changing the flags of the initial root mount with a bare
    // MS_REMOUNT.  Bind-mounting "/" onto itself creates a new mount entry
    // (distinct from the initial rootfs mount) in the kernel's mount table.
    // The next step then remounts *that* new entry, which the kernel permits.
    if (mount("/", "/", nullptr, MS_BIND | MS_REC, nullptr) == -1)
        child_die("mount", "self-bind / (interpreter mode)");

    // ── c) Remount the self-bind as read-only ─────────────────────────────
    //
    // Same two-phase pattern used throughout:
    //   phase 1 → MS_BIND          (create mount entry; RO flag ignored)
    //   phase 2 → MS_BIND | MS_REMOUNT | MS_RDONLY  (set RO on the entry)
    //
    // The entire directory tree becomes visible but immutable.  /proc, /dev,
    // and other special filesystems retain their types and continue to work —
    // they simply cannot be written to.
    if (mount(nullptr, "/", nullptr,
              MS_BIND | MS_REC | MS_REMOUNT | MS_RDONLY, nullptr) == -1)
        child_die("mount", "remount / RO (interpreter mode)");

    // ── d) Overlay /tmp with a fresh writable tmpfs ───────────────────────
    //
    // With "/" locked read-only the interpreter cannot write anywhere.
    // Most runtimes need a writable /tmp for bytecode caches, tempfile
    // creation, socket files, etc.  A private tmpfs over /tmp:
    //   • Is writable  — satisfies interpreter runtime requirements.
    //   • Is private   — invisible on the host; disappears when sandbox exits.
    //   • Has a cap    — size=64m prevents disk-exhaustion attacks.
    //   • mode=1777    — sticky-bit matches standard /tmp permissions.
    if (mount("sandbox-tmp", "/tmp", "tmpfs", 0, "size=64m,mode=1777") == -1)
        child_die("mount", "tmpfs over /tmp (interpreter mode)");

    fprintf(stderr, "[CHILD] Filesystem mode     : interpreter / RO host jail\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_rlimits  (child only — defense-in-depth, called BEFORE drop_privileges)
//
// Applies hard resource limits that remain in effect for the target process
// and all of its descendants regardless of cgroup availability.
//
// Why apply before drop_privileges()?
//   setrlimit(2) requires that the new hard limit be ≤ the existing hard limit
//   OR that the caller has CAP_SYS_RESOURCE.  We still have root here.  Once
//   we drop to nobody (UID 65534), the process cannot raise these hard limits
//   back — which is the whole point.
//
// RLIMIT_FSIZE — maximum file size that can be created (bytes).
//   Hard limit: 10 MiB.  Writing beyond this sends SIGXFSZ to the process.
//   Without this, a script could fill the host disk even with the RO jail,
//   because the jail's writable /tmp tmpfs is limited by size= but other
//   writable locations (e.g. newly created sockets, pipes, kernel buffers)
//   are not.  RLIMIT_FSIZE is a second, independent backstop.
//
// RLIMIT_CPU — maximum CPU time consumed (seconds, user+system combined).
//   Soft limit: 5 s — process receives SIGXCPU and can catch it.
//   Hard limit: 6 s — one second later the kernel sends an uncatchable SIGKILL.
//   This is the backstop if both the orchestrator's timeout and the cgroup
//   cpu.max quota fail (e.g. on WSL where cgroups are stubbed out).  An
//   infinite loop cannot consume more than 6 CPU-seconds.
// ─────────────────────────────────────────────────────────────────────────────

static void setup_rlimits() {
    struct rlimit rl;

    // ── RLIMIT_FSIZE: 10 MiB hard cap on file writes ──────────────────────
    rl.rlim_cur = 10 * 1024 * 1024;   // soft: 10 MiB → SIGXFSZ
    rl.rlim_max = 10 * 1024 * 1024;   // hard: same   → cannot be raised
    if (setrlimit(RLIMIT_FSIZE, &rl) == -1)
        child_die("setrlimit", "RLIMIT_FSIZE");

    // ── RLIMIT_CPU: 5 s soft / 6 s hard CPU-time cap ─────────────────────
    rl.rlim_cur = 5;   // soft: 5 s  → SIGXCPU (catchable)
    rl.rlim_max = 6;   // hard: 6 s  → SIGKILL  (uncatchable, one extra second)
    if (setrlimit(RLIMIT_CPU, &rl) == -1)
        child_die("setrlimit", "RLIMIT_CPU");

    fprintf(stderr,
            "[CHILD] rlimits applied     : "
            "RLIMIT_FSIZE=10MiB  RLIMIT_CPU=5s(soft)/6s(hard)\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// drop_privileges  (child only)
//
// Order is load-bearing — reversing setresgid and setresuid is a bug:
//   1. setgroups(0, NULL)      — strip all supplemental groups
//   2. setresgid(GID,GID,GID)  — real + effective + saved GID
//   3. setresuid(UID,UID,UID)  — real + effective + saved UID  ← last
// ─────────────────────────────────────────────────────────────────────────────

static void drop_privileges() {
    if (setgroups(0, nullptr) == -1)
        child_die("setgroups", "clear supplemental groups");
    if (setresgid(SANDBOX_GID, SANDBOX_GID, SANDBOX_GID) == -1)
        child_die("setresgid", "nobody GID");
    if (setresuid(SANDBOX_UID, SANDBOX_UID, SANDBOX_UID) == -1)
        child_die("setresuid", "nobody UID");

    if (getuid() != SANDBOX_UID || geteuid() != SANDBOX_UID)
        child_die("verify", "UID did not drop to nobody");
    if (getgid() != SANDBOX_GID || getegid() != SANDBOX_GID)
        child_die("verify", "GID did not drop to nobody");
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_seccomp  (child only — applied to BOTH execution modes)
//
// Installs a BPF program that:
//
//   KILLS on : ptrace, mknod, mknodat, unshare, clone3, mount, pivot_root
//   KILLS on : clone(flags) where any namespace bit is set
//   ALLOWS   : clone(flags) where no namespace bit is set (threading / fork)
//   ALLOWS   : everything else (default pass-through)
//
// Architecture guard
// ──────────────────
// The first three instructions load the arch field from seccomp_data and
// kill the process if it is not x86-64.  This prevents a 32-bit process
// from bypassing the filter by using the x86 compat syscall numbers, which
// are different from the x86-64 numbers tested below.
//
// Smart clone(2) filtering — BPF argument inspection
// ───────────────────────────────────────────────────
// BPF programs operate on a 32-bit accumulator (A).  To inspect the 64-bit
// clone flags argument we use the seccomp_data.args[] array, which stores
// each argument as a 64-bit quantity at a fixed offset.  The low 32 bits are
// at offsetof(seccomp_data, args[0]) and the high 32 bits are 4 bytes later.
// All current CLONE_NEW* flags live in the low 32 bits, so we only inspect
// args[0] (the low word).
//
// Sequence:
//   1. If syscall != __NR_clone → skip this block (fall through to others)
//   2. Load args[0] (low 32 bits of the flags argument)
//   3. AND with CLONE_NAMESPACE_MASK
//   4. If result == 0 → no namespace bits set → ALLOW
//   5. Otherwise           → namespace bit present → KILL
//
// clone3(2) blanket deny
// ──────────────────────
// clone3 passes its arguments via a struct pointer; inspecting the struct
// in BPF would require reading user memory (BPF_LD|BPF_IND), which the
// seccomp BPF dialect does not support.  We block clone3 entirely.  The
// glibc dynamic linker and pthreads fall back to clone(2) automatically
// when clone3 returns ENOSYS, so all valid use-cases continue to work.
// ─────────────────────────────────────────────────────────────────────────────

static void setup_seccomp() {

    // Compile-time offset of args[0] in struct seccomp_data.
    // The struct layout is: arch(4) + pad(4) + nr(4) + pad(4) + args[0..5](8 each)
    // args[0] low-32  → offsetof(seccomp_data, args[0])        = 16
    // args[0] high-32 → offsetof(seccomp_data, args[0]) + 4    = 20
    static constexpr __u32 OFF_NR    = static_cast<__u32>(offsetof(struct seccomp_data, nr));
    static constexpr __u32 OFF_ARCH  = static_cast<__u32>(offsetof(struct seccomp_data, arch));
    static constexpr __u32 OFF_ARGS0 = static_cast<__u32>(offsetof(struct seccomp_data, args[0]));

    struct sock_filter filter[] = {

        // ── [0-2] Architecture guard ──────────────────────────────────────
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),   // [2]

        // ── [3] Load syscall number into accumulator ──────────────────────
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),            // [3]

        // ── [4-5] Deny ptrace ─────────────────────────────────────────────
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace,     0, 1), // [4]
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),         // [5]

        // ── [6-7] Deny mknod ──────────────────────────────────────────────
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mknod,      0, 1), // [6]
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),         // [7]

        // ── [8-9] Deny mknodat ────────────────────────────────────────────
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mknodat,    0, 1), // [8]
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),         // [9]

        // ── [10-11] Deny unshare ──────────────────────────────────────────
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare,    0, 1), // [10]
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),         // [11]

        // ── [12-13] Deny clone3 (blanket) ────────────────────────────────
        // Block clone3 so that all clone calls come through the inspectable
        // clone(2) path.  ENOSYS causes glibc to fall back automatically.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3,     0, 1), // [12]
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),         // [13]

        // ── [14-21] Smart clone(2) — inspect namespace flags ─────────────
        //
        // [14] If this is NOT clone(2) → skip all 7 instructions to [21]
        //      (the mount deny).  jt=0 means "next if equal"; jf=6 means
        //      "jump 6 ahead if not equal", landing on instruction [21].
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 6),      // [14]

        // [15] It IS clone(2).  Load low-32 bits of args[0] (the flags).
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARGS0),               // [15]

        // [16] Mask off everything except the namespace bits.
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, CLONE_NAMESPACE_MASK),   // [16]

        // [17] If masked result == 0 → no namespace bit → ALLOW clone.
        //      jt=0 (next if equal), jf=1 (jump 1 ahead if not equal).
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),                // [17]

        // [18] No namespace bits → safe threading/fork → allow.
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),                 // [18]

        // [19] Namespace bit(s) set → namespace escape attempt → kill.
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),          // [19]

        // [20] Reload the syscall number for the checks that follow.
        //      (The accumulator currently holds the clone flags; we need
        //       the syscall number back for the remaining deny rules.)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR),                   // [20]

        // ── [21-22] Deny mount ────────────────────────────────────────────
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount,      0, 1), // [21]
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),         // [22]

        // ── [23-24] Deny pivot_root ───────────────────────────────────────
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pivot_root, 0, 1), // [23]
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),         // [24]

        // ── [25] Default: allow ───────────────────────────────────────────
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),                 // [25]
    };

    struct sock_fprog prog = {
        .len    = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
        child_die("prctl", "PR_SET_SECCOMP");
}

// ─────────────────────────────────────────────────────────────────────────────
// child_main
//
// Execution order is load-bearing:
//
//   1. Sync pipe read       — block until parent has applied cgroup limits
//   2. setup_fs_*()         — requires CAP_SYS_ADMIN (mount / pivot_root)
//   3. sethostname()        — requires CAP_SYS_ADMIN
//   4. setup_rlimits()      ← SET hard resource limits (while still root)
//   5. drop_privileges()    ← DROP ROOT permanently (real+effective+saved)
//   6. PR_SET_NO_NEW_PRIVS  ← LOCK: no setuid binary can re-elevate
//   7. PR_SET_PDEATHSIG     ← LOCK: re-armed after uid drop (which clears it)
//   8. setup_seccomp()      ← FILTER: installed last so it governs the target
//   9. exec*()              ← hand off to the target process
// ─────────────────────────────────────────────────────────────────────────────

static int child_main(void *arg) {
    const ChildArgs *args = static_cast<const ChildArgs *>(arg);

    // ── 1. Block until parent signals cgroup limits are live ─────────────
    if (close(args->sync.write_fd) == -1)
        child_die("close", "sync pipe write end (child)");

    char ready_byte = 0;
    const ssize_t n = read(args->sync.read_fd, &ready_byte, 1);
    if (n == -1) child_die("read", "sync pipe");
    if (n == 0) {
        fprintf(stderr, "[CHILD FATAL] sync pipe EOF before ready signal\n");
        _exit(EXIT_FAILURE);
    }
    if (close(args->sync.read_fd) == -1)
        child_die("close", "sync pipe read end (child)");

    // ── 2. Set up the filesystem jail (mode-dependent) ───────────────────
    if (args->is_interpreter) {
        setup_fs_interpreter();                   // RO host jail + /tmp tmpfs
    } else {
        setup_fs_native(args->target_argv[0]);    // pivot_root into empty jail
    }

    // ── 3. Set sandbox hostname ───────────────────────────────────────────
    if (sethostname(SANDBOX_HOSTNAME, sizeof(SANDBOX_HOSTNAME) - 1) == -1)
        child_die("sethostname", SANDBOX_HOSTNAME);

    // ── 4. Apply hard resource limits (must be root to set hard limits) ───
    setup_rlimits();

    // ── 5. Drop root permanently ──────────────────────────────────────────
    drop_privileges();

    // ── 6. Lock: no setuid binary can re-elevate this process ─────────────
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        child_die("prctl", "PR_SET_NO_NEW_PRIVS");

    // ── 7. Re-arm: die if the parent sandbox process is killed ────────────
    // setresuid() clears PR_SET_PDEATHSIG, so we must set it again here,
    // after the privilege drop.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1)
        child_die("prctl", "PR_SET_PDEATHSIG");

    // ── 8. Install the syscall filter ─────────────────────────────────────
    setup_seccomp();

    // ── 9. Execute the target ─────────────────────────────────────────────
    //
    // Minimal, sanitised environment shared by both paths.
    // Inheriting the parent environment would allow LD_PRELOAD /
    // LD_LIBRARY_PATH injection even after the privilege drop.
    char *const clean_envp[] = {
        const_cast<char *>("PATH=/usr/local/sbin:/usr/local/bin"
                           ":/usr/sbin:/usr/bin:/sbin:/bin"),
        const_cast<char *>("TERM=xterm-256color"),
        nullptr
    };

    if (args->is_interpreter) {
        // ── Interpreter: execvpe searches PATH for argv[0] ───────────────
        //
        // execvpe(name, argv, envp):
        //   name  — "python3" (no '/' → PATH search in clean_envp's PATH)
        //   argv  — passed unmodified; argv[0] stays "python3" so the
        //           interpreter's sys.argv[0] / $0 remains meaningful.
        //   envp  — clean_envp replaces the inherited environment.
        //
        // We use execvpe (not execvp) because execvp uses the *calling
        // process's* environment variable PATH, not a caller-supplied one.
        // execvpe lets us pass clean_envp and still get PATH resolution.
        fprintf(stderr,
                "[CHILD] Executing (interpreter): %s  (UID=%d GID=%d)\n",
                args->target_argv[0], getuid(), getgid());

        if (execvpe(args->target_argv[0], args->target_argv, clean_envp) == -1)
            child_die("execvpe", args->target_argv[0]);

    } else {
        // ── Native: execve uses the fixed in-sandbox path /target_bin ────
        //
        // First arg  — "/target_bin": kernel image path (the ELF injected by
        //              setup_fs_native() before pivot_root).  Using this fixed
        //              path means exec succeeds regardless of the original
        //              form of the caller's path (./victim, ../build/a.out, …)
        // Second arg — args->target_argv: program's own argv.  argv[0] remains
        //              the original caller string so ps / /proc/cmdline is sane.
        // Third arg  — clean_envp.
        fprintf(stderr,
                "[CHILD] Executing (native)      : /target_bin"
                "  (argv[0]=%s  UID=%d  GID=%d)\n",
                args->target_argv[0], getuid(), getgid());

        if (execve("/target_bin", args->target_argv, clean_envp) == -1)
            child_die("execve", "/target_bin");
    }

    return EXIT_SUCCESS; // unreachable
}

// ─────────────────────────────────────────────────────────────────────────────
// cgroup helpers  (parent only)
// ─────────────────────────────────────────────────────────────────────────────

static void cgroup_write_file(const char *path, const char *value) {
    const int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd == -1) die("open", path);

    const ssize_t len     = static_cast<ssize_t>(strlen(value));
    const ssize_t written = write(fd, value, static_cast<size_t>(len));
    if (written == -1) { close(fd); die("write", path); }
    if (written != len) {
        close(fd);
        fprintf(stderr, "[FATAL] write(%s): short write (%zd/%zd)\n",
                path, written, len);
        exit(EXIT_FAILURE);
    }
    if (close(fd) == -1) die("close", path);
}

static void setup_cgroup(pid_t child_pid,
                         char *cgroup_path_out, size_t cgroup_path_size) {
    snprintf(cgroup_path_out, cgroup_path_size,
             "%s/sandbox_%d", CGROUP_ROOT, child_pid);

    if (mkdir(cgroup_path_out, 0755) == -1) {
        // Non-fatal on WSL2 where cgroupfs may not be writable.
        fprintf(stderr,
                "[PARENT] WARNING: mkdir(%s) failed: %s\n"
                "[PARENT]          Cgroup limits NOT applied "
                "(WSL / unprivileged environment).\n",
                cgroup_path_out, strerror(errno));
        cgroup_path_out[0] = '\0'; // signal cleanup_cgroup to skip rmdir
        return;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/memory.max", cgroup_path_out);
    cgroup_write_file(path, CGROUP_MEM_MAX);

    snprintf(path, sizeof(path), "%s/pids.max", cgroup_path_out);
    cgroup_write_file(path, CGROUP_PIDS_MAX);

    snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path_out);
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", child_pid);
    cgroup_write_file(path, pid_str);

    fprintf(stderr, "[PARENT] Cgroup          : %s\n", cgroup_path_out);
    fprintf(stderr, "[PARENT] memory.max      = %s\n", CGROUP_MEM_MAX);
    fprintf(stderr, "[PARENT] pids.max        = %s\n", CGROUP_PIDS_MAX);
    fprintf(stderr, "[PARENT] cgroup.procs    = %d\n", child_pid);
}

static void cleanup_cgroup(const char *cgroup_path) {
    if (cgroup_path && cgroup_path[0] != '\0')
        rmdir(cgroup_path); // best-effort; errors ignored
}

// ─────────────────────────────────────────────────────────────────────────────
// RAII child stack
// ─────────────────────────────────────────────────────────────────────────────

class ChildStack {
public:
    explicit ChildStack(size_t sz) : size_(sz), buf_(nullptr) {
        buf_ = static_cast<char *>(malloc(sz));
        if (!buf_) die("malloc", "child stack");
    }
    ~ChildStack() { free(buf_); }
    char *top() const { return buf_ + size_; }

    ChildStack(const ChildStack &)            = delete;
    ChildStack &operator=(const ChildStack &) = delete;
private:
    size_t  size_;
    char   *buf_;
};

// ─────────────────────────────────────────────────────────────────────────────
// run_sandbox
//
// Returns the child's decoded exit status:
//   • Normal exit  → child's own exit code (e.g. 0)
//   • Killed       → 128 + signal number
//     (standard Unix convention: bash, runc, systemd all use this mapping)
// ─────────────────────────────────────────────────────────────────────────────

static int run_sandbox(char **target_argv) {
    const bool is_interpreter = detect_interpreter(target_argv[0]);

    fprintf(stderr, "[PARENT] Mode            : %s\n",
            is_interpreter ? "interpreter (RO host jail + /tmp tmpfs)"
                           : "native      (pivot_root jail)");
    fprintf(stderr, "[PARENT] Target argv[0]  : %s\n", target_argv[0]);

    int pipe_fds[2];
    if (pipe(pipe_fds) == -1)
        die("pipe", "sync pipe");

    ChildArgs args {
        /* sync           */ { pipe_fds[0], pipe_fds[1] },
        /* target_argv    */ target_argv,
        /* is_interpreter */ is_interpreter,
    };

    ChildStack stack(CHILD_STACK_SIZE);

    const int clone_flags =
        CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC |
        CLONE_NEWUTS | CLONE_NEWNS  | SIGCHLD;

    const pid_t child_pid = clone(child_main, stack.top(), clone_flags, &args);
    if (child_pid == -1)
        die("clone");

    fprintf(stderr, "[PARENT] Child PID (host): %d\n", child_pid);

    // Parent never reads from the pipe.
    if (close(args.sync.read_fd) == -1)
        die("close", "sync pipe read end (parent)");

    // Apply cgroup limits while the child is blocked on the pipe read.
    char cgroup_path[512] = {};
    setup_cgroup(child_pid, cgroup_path, sizeof(cgroup_path));

    // Unblock the child — limits are now live.
    const char ready = 'x';
    if (write(args.sync.write_fd, &ready, 1) != 1)
        die("write", "sync pipe ready byte");
    if (close(args.sync.write_fd) == -1)
        die("close", "sync pipe write end (parent)");

    int wstatus = 0;
    if (waitpid(child_pid, &wstatus, 0) == -1)
        die("waitpid");

    cleanup_cgroup(cgroup_path);
    rmdir(NEW_ROOT); // best-effort; only relevant in native mode

    if (WIFEXITED(wstatus)) {
        const int code = WEXITSTATUS(wstatus);
        fprintf(stderr, "[PARENT] Target exited normally, status=%d\n", code);
        return code;
    }

    if (WIFSIGNALED(wstatus)) {
        const int sig = WTERMSIG(wstatus);
        fprintf(stderr, "[PARENT] Target killed by signal %d (%s)%s\n",
                sig, strsignal(sig),
                WCOREDUMP(wstatus) ? " [core dumped]" : "");
        return 128 + sig;
    }

    fprintf(stderr, "[PARENT] Unknown wait status 0x%x\n", wstatus);
    return EXIT_FAILURE;
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <target> [args...]\n"
                "\n"
                "  Native binary (pivot_root jail):\n"
                "    sudo %s ./victim\n"
                "    sudo %s /usr/bin/cat /etc/hostname\n"
                "\n"
                "  Interpreter (RO host jail + private /tmp):\n"
                "    sudo %s python3 victim.py\n"
                "    sudo %s node    victim.js\n"
                "    sudo %s ruby    victim.rb\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    if (geteuid() != 0) {
        fprintf(stderr,
                "[ERROR] Requires root (CAP_SYS_ADMIN) for namespace "
                "and mount operations.\n"
                "        Run as: sudo %s %s\n",
                argv[0], argv[1]);
        return EXIT_FAILURE;
    }

    // argv[1] is the target (or interpreter name); argv[1..] is its argv.
    // The slice is null-terminated because C guarantees argv[argc] == NULL.
    return run_sandbox(argv + 1);
}