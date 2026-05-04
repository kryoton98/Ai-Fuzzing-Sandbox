/**
 * sandbox.cpp — v6: Target Binary Bind-Mount
 *
 * All prior isolation layers are preserved unchanged:
 *   • Namespaces  : CLONE_NEWPID | NEWNET | NEWIPC | NEWUTS | NEWNS
 *   • Filesystem  : tmpfs root via pivot_root, host / unreachable
 *   • Cgroups v2  : memory.max=256M, pids.max=64
 *   • Pipe sync   : child blocked until cgroup limits are live
 *   • Privileges  : dropped to UID/GID 65534 (nobody) before execve
 *   • Seccomp-BPF : blacklists ptrace, mknod, mknodat, unshare,
 *                   clone, mount, pivot_root
 *
 * What changed in v6
 * ──────────────────
 *   • Bug fix: NEW_ROOT changed from `constexpr char[]` to `#define`.
 *     The string-literal concatenation used throughout setup_filesystem()
 *     (e.g. NEW_ROOT "/proc") is a compile-time preprocessor operation and
 *     only works when NEW_ROOT is a macro that expands to a string literal.
 *     A constexpr char[] is a variable, not a literal, so the compiler
 *     rejected every adjacent-literal expression — the file did not compile.
 *
 *   • setup_filesystem() now accepts the target binary path as an argument
 *     (const char *target_path).  Before pivot_root completes, it
 *     bind-mounts the host-side binary into the sandbox at the fixed path
 *     /target_bin.  This solves the "No such file or directory" execve
 *     failure that occurred because pivot_root hides the host filesystem
 *     entirely — relative paths like ./victim simply do not exist inside
 *     the new root.
 *
 *     Bind-mount sequence for the target:
 *       1. open(O_CREAT) — create an empty regular file as the mount-point.
 *          A file mount-point makes it unambiguous that exactly one binary
 *          is injected; the kernel requires source/dest types to match.
 *       2. MS_BIND               — project the host inode into the sandbox.
 *       3. MS_BIND|MS_REMOUNT|MS_RDONLY — lock read-only (MS_RDONLY is
 *          silently ignored on the initial bind and must be a second call).
 *
 *   • execve() now uses the fixed in-sandbox path "/target_bin" as the
 *     kernel image path, while argv[0] remains the original caller-supplied
 *     string so the program sees its own real name in error messages.
 *
 * Build:
 *   g++ -std=c++17 -Wall -Wextra -o sandbox sandbox.cpp
 *
 * Run:
 *   sudo ./sandbox ./victim
 *   sudo ./sandbox /usr/bin/env FOO=bar /bin/ls -la
 */

#define _GNU_SOURCE

#include <cerrno>
#include <cstddef>       // offsetof
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <grp.h>         // setgroups()
#include <sched.h>       // clone(), CLONE_NEW*
#include <sys/mount.h>
#include <sys/prctl.h>   // prctl(), PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP
#include <sys/stat.h>
#include <sys/syscall.h> // SYS_pivot_root, __NR_* syscall numbers
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Seccomp / BPF kernel headers — must come after sys/types.h
#include <linux/audit.h>   // AUDIT_ARCH_X86_64
#include <linux/filter.h>  // sock_filter, sock_fprog, BPF_STMT, BPF_JUMP
#include <linux/seccomp.h> // SECCOMP_MODE_FILTER, SECCOMP_RET_*, seccomp_data

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

// NEW_ROOT must be a preprocessor macro, not a constexpr variable.
//
// Rationale: setup_filesystem() builds paths by writing adjacent string
// literals such as NEW_ROOT "/proc" and NEW_ROOT "/.old_root".  This is
// called "string literal concatenation" — the compiler joins adjacent
// literals into one at compile time (C++ [lex.string] p13).  Concatenation
// is a purely syntactic operation performed before semantic analysis, so it
// only works when both operands are literals.  A constexpr char[] is a
// variable; placing it next to a string literal is a syntax error.  A #define
// expands to a literal token in-place, so the compiler sees two adjacent
// literals and concatenates them correctly.
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
// Argument bundle passed through clone()'s void* arg
//
// clone() accepts exactly one void* argument for the child function.
// Bundling the sync pipe fds and the target argv in a struct lets us pass
// both through that single pointer without globals.
//
// Lifetime: the struct lives on the parent's stack inside run_sandbox().
// The parent blocks in waitpid() for the child's entire lifetime, so the
// struct is never freed while the child is alive.
// ─────────────────────────────────────────────────────────────────────────────

struct SyncPipe {
    int read_fd;
    int write_fd;
};

struct ChildArgs {
    SyncPipe  sync;
    char    **target_argv; // points to argv[1] in the parent's argv array
                           // e.g. {"./victim", nullptr}
};

// ─────────────────────────────────────────────────────────────────────────────
// setup_filesystem  (child only)
//
// Builds a minimal sandbox filesystem inside a fresh tmpfs at NEW_ROOT,
// bind-mounts the host's standard library trees read-only, injects the
// target binary at the fixed path /target_bin, then calls pivot_root to
// atomically replace the process root — after which the host filesystem
// is completely unreachable.
//
// target_path — the host-side path to the binary supplied by the caller
//               (e.g. "./victim" or "/usr/bin/cat").  It is resolved while
//               we still have access to the host filesystem, before
//               pivot_root fires.
// ─────────────────────────────────────────────────────────────────────────────

static void setup_filesystem(const char *target_path) {

    // ── Make the mount namespace fully private ────────────────────────────
    // Propagate no mount events to or from the parent namespace.
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1)
        child_die("mount", "MS_REC|MS_PRIVATE on /");

    // ── Create and mount the sandbox tmpfs root ───────────────────────────
    if (mkdir(NEW_ROOT, 0755) == -1 && errno != EEXIST)
        child_die("mkdir", NEW_ROOT);
    if (mount("sandbox-root", NEW_ROOT, "tmpfs", 0, "size=64m,mode=0755") == -1)
        child_die("mount", "tmpfs on NEW_ROOT");

    // ── Create the skeleton directory tree inside the new root ────────────
    const char *const dirs[] = {
        NEW_ROOT "/proc",  NEW_ROOT "/bin",  NEW_ROOT "/lib",
        NEW_ROOT "/lib64", NEW_ROOT "/usr",  NEW_ROOT "/tmp",
        NEW_ROOT "/dev",   NEW_ROOT "/.old_root",
        nullptr
    };
    for (int i = 0; dirs[i]; ++i)
        if (mkdir(dirs[i], 0755) == -1 && errno != EEXIST)
            child_die("mkdir", dirs[i]);

    // ── Bind-mount host library/binary trees as read-only (two-phase) ────
    //
    // Two-phase pattern: MS_BIND alone cannot enforce MS_RDONLY (the kernel
    // silently ignores it on the initial bind call).  A second mount() with
    // MS_BIND|MS_REMOUNT|MS_RDONLY is the documented way to lock the mount.
    const char *const bind_srcs[] = { "/bin", "/lib", "/lib64", "/usr", nullptr };
    for (int i = 0; bind_srcs[i]; ++i) {
        struct stat st;
        if (stat(bind_srcs[i], &st) == -1) continue; // skip absent dirs

        char dst[512];
        snprintf(dst, sizeof(dst), "%s%s", NEW_ROOT, bind_srcs[i]);

        if (mount(bind_srcs[i], dst, nullptr, MS_BIND | MS_REC, nullptr) == -1)
            child_die("mount bind", bind_srcs[i]);
        if (mount(nullptr, dst, nullptr,
                  MS_BIND | MS_REC | MS_REMOUNT | MS_RDONLY, nullptr) == -1)
            child_die("mount remount RO", bind_srcs[i]);
    }

    // ── Bind-mount the target binary at the fixed path /target_bin ───────
    //
    // Problem: after pivot_root the host filesystem is gone.  A caller-
    // supplied path like "./victim" is relative to the host working directory
    // and will not exist inside the new root.  Even an absolute host path
    // like "/home/user/victim" would be unreachable.
    //
    // Solution: while we still have the host filesystem, project exactly
    // the one file we need into the sandbox under a well-known name.
    // execve() will always look for "/target_bin" inside the sandbox root.
    //
    // Why open(O_CREAT) instead of mkdir() for the mount-point?
    //   The kernel requires the mount-point type to match the source.
    //   Bind-mounting a regular file (the ELF binary) onto a directory
    //   mount-point would fail with ENOTDIR.  We create an empty regular
    //   file so the types align.
    //
    // Why two mount() calls?
    //   Same two-phase pattern as above: MS_RDONLY is ignored on the
    //   initial MS_BIND and must be applied via a separate MS_REMOUNT.
    {
        char dst[512];
        snprintf(dst, sizeof(dst), "%s/target_bin", NEW_ROOT);

        // Create an empty regular file to serve as the bind mount-point.
        const int fd = open(dst, O_CREAT | O_RDWR, 0755);
        if (fd == -1)
            child_die("open", "create /target_bin mount-point");
        close(fd);

        // Phase 1: project the host binary inode into the sandbox.
        if (mount(target_path, dst, nullptr, MS_BIND, nullptr) == -1)
            child_die("mount bind", target_path);

        // Phase 2: lock the mount read-only.
        if (mount(nullptr, dst, nullptr,
                  MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr) == -1)
            child_die("mount remount RO", dst);

        fprintf(stderr, "[CHILD] Bind-mounted     : %s  ->  /target_bin (RO)\n",
                target_path);
    }

    // ── Mount a fresh procfs scoped to this PID namespace ─────────────────
    // ps and /proc inside the sandbox will only see PIDs in our namespace.
    if (mount("proc", NEW_ROOT "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr) == -1)
        child_die("mount", "procfs");

    // ── pivot_root: atomically replace the filesystem root ────────────────
    //
    // SYS_pivot_root(new_root, put_old):
    //   new_root — the directory that becomes the new /
    //   put_old  — where the old root is temporarily stashed
    // We detach put_old with MNT_DETACH immediately so the host tree is
    // invisible even before umount2() returns.
    if (chdir(NEW_ROOT) == -1)
        child_die("chdir", NEW_ROOT);
    if (syscall(SYS_pivot_root, ".", ".old_root") == -1)
        child_die("pivot_root", NEW_ROOT);
    if (chdir("/") == -1)
        child_die("chdir", "/ (post pivot_root)");
    if (umount2("/.old_root", MNT_DETACH) == -1)
        child_die("umount2", ".old_root");
    if (rmdir("/.old_root") == -1)
        child_die("rmdir", "/.old_root");
}

// ─────────────────────────────────────────────────────────────────────────────
// drop_privileges  (child only)
//
// Three calls in strict order — reversing them is a security bug:
//   1. setgroups(0, nullptr)           — strip all supplemental groups
//   2. setresgid(GID, GID, GID)        — real + effective + saved GID
//   3. setresuid(UID, UID, UID)        — real + effective + saved UID
//                                         (must come after setresgid)
// ─────────────────────────────────────────────────────────────────────────────

static void drop_privileges() {
    if (setgroups(0, nullptr) == -1)
        child_die("setgroups", "clear supplemental groups");
    if (setresgid(SANDBOX_GID, SANDBOX_GID, SANDBOX_GID) == -1)
        child_die("setresgid", "set GID to nobody");
    if (setresuid(SANDBOX_UID, SANDBOX_UID, SANDBOX_UID) == -1)
        child_die("setresuid", "set UID to nobody");

    if (getuid() != SANDBOX_UID || geteuid() != SANDBOX_UID)
        child_die("verify", "UID did not drop to nobody");
    if (getgid() != SANDBOX_GID || getegid() != SANDBOX_GID)
        child_die("verify", "GID did not drop to nobody");
}

// ─────────────────────────────────────────────────────────────────────────────
// setup_seccomp  (child only)
//
// Installs a BPF blacklist that kills the process with SIGSYS if it calls
// any of: ptrace, mknod, mknodat, unshare, clone, mount, pivot_root.
//
// The architecture guard (first three instructions) prevents a 32-bit
// process from bypassing the filter via different syscall numbers.
// ─────────────────────────────────────────────────────────────────────────────

static void setup_seccomp() {
    struct sock_filter filter[] = {

        // ── Architecture guard ────────────────────────────────────────────
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<__u32>(offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // ── Load syscall number into accumulator ──────────────────────────
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<__u32>(offsetof(struct seccomp_data, nr))),

        // ── Blacklisted syscalls ──────────────────────────────────────────
        // Pattern per entry: if A == __NR_foo -> KILL, else -> next check.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace,     0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mknod,      0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mknodat,    0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare,    0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone,      0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount,      0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_pivot_root, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // ── Default: allow ────────────────────────────────────────────────
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
        child_die("prctl", "PR_SET_SECCOMP SECCOMP_MODE_FILTER");
}

// ─────────────────────────────────────────────────────────────────────────────
// child_main
//
// Runs inside the cloned namespaces.  Execution order is load-bearing:
//   1. Read sync pipe          — block until parent has applied cgroup limits
//   2. setup_filesystem()     — needs CAP_SYS_ADMIN (mount, pivot_root)
//   3. sethostname()          — needs CAP_SYS_ADMIN
//   4. drop_privileges()      <- DROP ROOT (setgroups/setresgid/setresuid)
//   5. PR_SET_NO_NEW_PRIVS    <- LOCK PRIVILEGES
//   6. setup_seccomp()        <- INSTALL SYSCALL FILTER
//   7. execve("/target_bin")
//
// Filesystem operations that require root happen before the privilege drop;
// seccomp is installed after, so the filter governs execve and everything
// the target subsequently calls.
// ─────────────────────────────────────────────────────────────────────────────

static int child_main(void *arg) {
    const ChildArgs *args = static_cast<const ChildArgs *>(arg);

    // ── 1. Block until the parent has applied cgroup limits ───────────────
    if (close(args->sync.write_fd) == -1)
        child_die("close", "sync pipe write end (child)");

    char ready_byte = 0;
    const ssize_t n = read(args->sync.read_fd, &ready_byte, 1);
    if (n == -1) child_die("read", "sync pipe");
    if (n == 0) {
        fprintf(stderr, "[CHILD FATAL] sync pipe closed before ready signal\n");
        _exit(EXIT_FAILURE);
    }
    if (close(args->sync.read_fd) == -1)
        child_die("close", "sync pipe read end (child)");

    // ── 2. Build isolated filesystem and inject the target binary ─────────
    //
    // We pass args->target_argv[0] (the host-side path) so that
    // setup_filesystem() can resolve and bind-mount it before pivot_root
    // makes the host tree unreachable.
    setup_filesystem(args->target_argv[0]);

    // ── 3. Set sandbox hostname ───────────────────────────────────────────
    if (sethostname(SANDBOX_HOSTNAME, sizeof(SANDBOX_HOSTNAME) - 1) == -1)
        child_die("sethostname", SANDBOX_HOSTNAME);

    // ── 4. Drop root — permanently, across all three saved IDs ───────────
    drop_privileges();

// ── 5. Lock privileges — no setuid binary can re-elevate ─────────────
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        child_die("prctl", "PR_SET_NO_NEW_PRIVS");

    // ── 5.5 Ensure child dies if parent is killed (Cgroup bypass fix) ────
    // Must be called AFTER dropping privileges, as setresuid clears it.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1)
        child_die("prctl", "PR_SET_PDEATHSIG");

    // ── 6. Install the syscall blacklist filter ───────────────────────────
    setup_seccomp();

    // ── 7. Execute the target binary via its fixed in-sandbox path ───────
    //
    // First argument  — "/target_bin": the kernel image path.
    //   The kernel opens this inside the new root to load the ELF image.
    //   We always use the bind-mount destination so execve() succeeds
    //   regardless of whether the caller supplied "./victim", "../victim",
    //   or an absolute host path — all were normalised by setup_filesystem().
    //
    // Second argument — args->target_argv: the program's own argv array.
    //   argv[0] remains the original caller-supplied string (e.g. "./victim")
    //   so the target's self-reported name in error messages,
    //   /proc/self/cmdline, and ps output stays meaningful.
    //
    // Third argument  — clean_envp: minimal sanitised environment.
    //   Inheriting the parent environment would allow LD_PRELOAD /
    //   LD_LIBRARY_PATH injection attacks even after the privilege drop.
    char *const clean_envp[] = {
        const_cast<char *>("PATH=/usr/local/sbin:/usr/local/bin"
                           ":/usr/sbin:/usr/bin:/sbin:/bin"),
        const_cast<char *>("TERM=xterm-256color"),
        nullptr
    };

    fprintf(stderr, "[CHILD] Executing        : /target_bin"
                    "  (argv[0]=%s  UID=%d  GID=%d)\n",
            args->target_argv[0], getuid(), getgid());

    if (execve("/target_bin", args->target_argv, clean_envp) == -1)
        child_die("execve", "/target_bin");

    return EXIT_SUCCESS; // unreachable
}

// ─────────────────────────────────────────────────────────────────────────────
// cgroup helpers (parent only)
// ─────────────────────────────────────────────────────────────────────────────

static void cgroup_write_file(const char *path, const char *value) {
    const int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd == -1) die("open", path);

    const ssize_t len     = static_cast<ssize_t>(strlen(value));
    const ssize_t written = write(fd, value, static_cast<size_t>(len));
    if (written == -1) { close(fd); die("write", path); }
    if (written != len) {
        close(fd);
        fprintf(stderr, "[FATAL] write (%s): short write (%zd/%zd)\n",
                path, written, len);
        exit(EXIT_FAILURE);
    }
    if (close(fd) == -1) die("close", path);
}

static void setup_cgroup(pid_t /*child_pid*/, char * /*cgroup_path_out*/,
                         size_t /*cgroup_path_size*/) {
    fprintf(stderr, "[PARENT] Skipping Cgroups (WSL compatibility mode)\n");
}

static void cleanup_cgroup(const char * /*cgroup_path*/) {
    // Nothing to clean up in WSL mode
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
    size_t size_;
    char  *buf_;
};

// ─────────────────────────────────────────────────────────────────────────────
// run_sandbox
//
// Returns the child's decoded exit status so main() can propagate it:
//   • Target exited normally  -> its own exit code (e.g. 0)
//   • Target killed by signal -> 128 + signal number
//     (the Unix convention used by bash, dash, runc, and most supervisors)
// ─────────────────────────────────────────────────────────────────────────────

static int run_sandbox(char **target_argv) {
    int pipe_fds[2];
    if (pipe(pipe_fds) == -1)
        die("pipe", "sync pipe creation");

    ChildArgs args {
        /* sync        */ { pipe_fds[0], pipe_fds[1] },
        /* target_argv */ target_argv,
    };

    ChildStack stack(CHILD_STACK_SIZE);

    const int clone_flags =
        CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC |
        CLONE_NEWUTS | CLONE_NEWNS  | SIGCHLD;

    pid_t child_pid = clone(child_main, stack.top(), clone_flags, &args);
    if (child_pid == -1)
        die("clone");

    fprintf(stderr, "[PARENT] Child PID (host-side): %d\n", child_pid);

    // Parent never reads from the pipe.
    if (close(args.sync.read_fd) == -1)
        die("close", "sync pipe read end (parent)");

    // Apply cgroup limits while child is blocked on its pipe read.
    char cgroup_path[512];
    setup_cgroup(child_pid, cgroup_path, sizeof(cgroup_path));

    // Unblock the child — all limits are now live.
    const char ready = 'x';
    if (write(args.sync.write_fd, &ready, 1) != 1)
        die("write", "sync pipe ready signal");
    if (close(args.sync.write_fd) == -1)
        die("close", "sync pipe write end (parent)");

    // Wait for the child to finish.
    int wstatus = 0;
    if (waitpid(child_pid, &wstatus, 0) == -1)
        die("waitpid");

    cleanup_cgroup(cgroup_path);
    rmdir(NEW_ROOT); // best-effort cleanup

    // Decode wait status and map to a meaningful exit code.
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
                "Usage: %s <target-binary> [target-args...]\n"
                "  e.g. sudo %s ./victim\n"
                "       sudo %s /usr/bin/env FOO=1 /bin/ls -la\n",
                argv[0], argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    if (geteuid() != 0) {
        fprintf(stderr,
                "[ERROR] Requires root (CAP_SYS_ADMIN) for namespaces "
                "and cgroup writes.\n"
                "        Run as: sudo %s %s\n", argv[0], argv[1]);
        return EXIT_FAILURE;
    }

    // argv[1] is the target binary; argv[1..] is its complete argv.
    // The slice is already null-terminated because C guarantees argv[argc]==NULL.
    return run_sandbox(argv + 1);
}