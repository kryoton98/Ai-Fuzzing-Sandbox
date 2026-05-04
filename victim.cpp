#include <iostream>
#include <string>

int main() {
    std::string secret;
    std::cin >> secret;

    if (!secret.empty() && secret[0] == '!') {
        std::cerr << "[victim] Trapped in a logic loop...\n";
        while (true) {
            // Spinning forever
        }
    }

    std::cout << "Input processed: " << secret << "\n";
    return 0;
}