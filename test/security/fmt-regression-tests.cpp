// Exact upstream CVE-2018-1000052 regression from fmtlib/fmt commit 8cf30aa.
#define FMT_HEADER_ONLY
#include "../../Vendor/spdlog/fmt/bundled/format.h"
#include <iostream>

int main()
{
    const std::string result = fmt::format("...........{:<77777.7p}", "foo");
    if (result.size() != 77788 || result.substr(0, 11) != "...........") {
        std::cerr << "Complex pointer formatting produced corrupt output\n";
        return 1;
    }
    std::cout << "Complex pointer formatting regression passed\n";
    return 0;
}
