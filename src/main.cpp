// msmap – Mikrotik Firewall Log Viewer
// Build skeleton: verifies all three library dependencies resolve correctly.

#include <maxminddb.h>
#include <microhttpd.h>
#include <sqlite3.h>

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

constexpr std::string_view kVersion{"0.1.0"};

}  // namespace

int main() {
    std::cout << "msmap v" << kVersion << "\n"
              << "  sqlite3    " << sqlite3_libversion() << "\n"
              << "  microhttpd " << MHD_get_version() << "\n";
    return EXIT_SUCCESS;
}
