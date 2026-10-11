// Password Strength Scanner (C++17)
// Build:  g++ -std=c++17 -O2 -o scanner password_scanner.cpp
// Run:    ./scanner            (interactive)
//         ./scanner "MyP@ss1"  (single check)

#include <algorithm>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

struct Check {
    std::string name;
    bool passed;
};

struct Result {
    std::vector<Check> checks;
    double bits;
    int level; // 0..4
};

static const std::vector<std::string> COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
    "football", "login", "passw0rd", "111111", "000000", "1q2w3e",
    "master", "sunshine"};

static const char *LABELS[] = {"Very weak", "Weak", "Fair", "Strong", "Very strong"};

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool hasRepeat(const std::string &p) {
    for (size_t i = 0; i + 2 < p.size(); ++i)
        if (p[i] == p[i + 1] && p[i] == p[i + 2]) return true;
    return false;
}

bool hasSequence(const std::string &p) {
    std::string s = toLower(p);
    for (size_t i = 0; i + 2 < s.size(); ++i) {
        int a = s[i], b = s[i + 1], c = s[i + 2];
        if ((b - a == 1 && c - b == 1) || (a - b == 1 && b - c == 1)) return true;
    }
    return false;
}

bool isCommon(const std::string &p) {
    std::string s = toLower(p);
    for (const auto &w : COMMON)
        if (s.find(w) != std::string::npos) return true;
    return false;
}

Result analyze(const std::string &p) {
    bool lower = false, upper = false, digit = false, symbol = false;
    for (unsigned char c : p) {
        if (std::islower(c)) lower = true;
        else if (std::isupper(c)) upper = true;
        else if (std::isdigit(c)) digit = true;
        else symbol = true;
    }

    Result r;
    bool common = isCommon(p), repeat = hasRepeat(p), seq = hasSequence(p);
    r.checks = {
        {"At least 12 characters", p.size() >= 12},
        {"Has lowercase letters", lower},
        {"Has uppercase letters", upper},
        {"Has numbers", digit},
        {"Has symbols", symbol},
        {"Not a common password", !common},
        {"No repeated runs (aaa, 111)", !repeat},
        {"No simple sequences (abc, 123)", !seq}};

    int pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0);
    r.bits = pool ? p.size() * std::log2(static_cast<double>(pool)) : 0.0;
    if (common) r.bits = std::min(r.bits, 20.0);
    if (repeat) r.bits *= 0.8;
    if (seq) r.bits *= 0.85;

    r.level = r.bits < 28 ? 0 : r.bits < 40 ? 1 : r.bits < 60 ? 2 : r.bits < 80 ? 3 : 4;
    return r;
}

std::string crackTime(double bits) {
    const double guessesPerSec = 1e10; // fast offline attack
    double sec = std::pow(2.0, bits) / 2.0 / guessesPerSec;
    const double year = 31557600.0;
    auto plural = [](long long n, const char *u) {
        return std::to_string(n) + " " + u + (n > 1 ? "s" : "");
    };
    if (sec < 1) return "Instantly";
    if (sec >= year * 1e9) return "Billions of years+";
    if (sec >= year * 1e6) return plural(std::llround(sec / year / 1e6), "million year");
    if (sec >= year * 1e3) return plural(std::llround(sec / year / 1e3), "thousand year");
    if (sec >= year) return plural(std::llround(sec / year), "year");
    if (sec >= 86400) return plural(std::llround(sec / 86400), "day");
    if (sec >= 3600) return plural(std::llround(sec / 3600), "hour");
    if (sec >= 60) return plural(std::llround(sec / 60), "minute");
    return plural(std::llround(sec), "second");
}

void report(const std::string &p) {
    Result r = analyze(p);
    std::cout << "\n[";
    for (int i = 0; i < 5; ++i) std::cout << (i <= r.level ? '#' : '-');
    std::cout << "] " << LABELS[r.level] << "\n";
    std::cout << "Entropy      : " << std::fixed << std::setprecision(0) << r.bits << " bits\n";
    std::cout << "Time to crack: " << crackTime(r.bits) << "\n\n";

    const Check *firstFail = nullptr;
    for (const auto &c : r.checks) {
        std::cout << (c.passed ? "  [PASS] " : "  [FAIL] ") << c.name << "\n";
        if (!c.passed && !firstFail) firstFail = &c;
    }
    std::cout << "\n";
    if (firstFail)
        std::cout << "Tip: fix \"" << firstFail->name
                  << "\". A passphrase of 4+ random words is easy to remember and hard to crack.\n";
    else
        std::cout << "Looks good. Use a unique password per account and a password manager.\n";
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        report(argv[1]);
        return 0;
    }
    std::cout << "Password Strength Scanner (type 'quit' to exit)\n";
    std::string line;
    while (true) {
        std::cout << "\nPassword> ";
        if (!std::getline(std::cin, line) || line == "quit") break;
        if (line.empty()) continue;
        report(line);
    }
    return 0;
}
