/**
 * victim.cpp — Deliberately Vulnerable Fuzzing Target
 *
 * Reads one line from stdin and reacts to three exact inputs:
 *
 *   "CRASH"  → dereferences a null pointer → SIGSEGV (signal 11)
 *              The sandbox will report exit code 128+11 = 139.
 *
 *   "LOOP"   → spins in an infinite loop forever.
 *              The Python orchestrator's 2-second timeout will fire,
 *              and the sandbox will kill the child via SIGKILL.
 *
 *   anything → prints "Safe" and exits 0.
 *
 * Build:
 *   g++ -std=c++17 -O0 -fno-stack-protector -o victim victim.cpp
 *
 * The -O0 / -fno-stack-protector flags prevent the compiler from
 * optimising away the deliberate null-dereference or the infinite loop.
 */

#include <iostream>
#include <string>

int main() {
    std::string input;

    // Read a single line.  getline() strips the trailing '\n' so
    // exact-string comparison works without manual trimming.
    if (!std::getline(std::cin, input)) {
        std::cerr << "[victim] stdin closed without input\n";
        return 1;
    }

    // ── Trigger 1: Segmentation Fault ────────────────────────────────────────
    // Assign nullptr to a volatile pointer so the compiler cannot prove
    // the dereference is unreachable and silently remove it.
    if (input == "CRASH") {
        std::cerr << "[victim] CRASH input received — triggering SIGSEGV\n";
        volatile int *null_ptr = nullptr;
        *null_ptr = 0xDEAD; // deliberate null-dereference → SIGSEGV
        return 0;           // unreachable, but silences -Wreturn-type
    }

    // ── Trigger 2: Infinite Loop (resource exhaustion / hang) ────────────────
    // volatile prevents the loop body from being optimised away.
    if (input == "LOOP") {
        std::cerr << "[victim] LOOP input received — spinning forever\n";
        volatile bool spin = true;
        while (spin) { /* intentional infinite loop */ }
        return 0; // unreachable
    }

    // ── Safe path ─────────────────────────────────────────────────────────────
    std::cout << "Safe\n";
    return 0;
}