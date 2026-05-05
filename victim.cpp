#include <iostream>
#include <string>

int main() {
    std::string input;
    if (!std::getline(std::cin, input)) {
        std::cerr << "[victim] stdin closed\n";
        return 1;
    }

    // Trigger 1: deliberate null-dereference -> SIGSEGV
    if (input == "CRASH") {
        std::cerr << "[victim] CRASH -> triggering SIGSEGV\n";
        volatile int *p = nullptr;
        *p = 0xDEAD;
        return 0;
    }

    // Trigger 2: infinite spin -> timeout / SIGKILL
    if (input == "LOOP") {
        std::cerr << "[victim] LOOP -> spinning forever\n";
        volatile bool spin = true;
        while (spin) {}
        return 0;
    }

    std::cout << "Safe: " << input << "\n";
    return 0;
}