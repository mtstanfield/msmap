// msmap – Mikrotik Firewall Log Viewer

#include "db.h"
#include "listener.h"

#include <cstdlib>
#include <iostream>

namespace {

constexpr int         kListenPort{5140};
constexpr const char* kDbPath    {"msmap.db"};

} // namespace

int main() {
    msmap::Database db{kDbPath};
    if (!db.valid()) {
        std::clog << "[FATAL] failed to open database: " << kDbPath << '\n';
        return EXIT_FAILURE;
    }

    msmap::run_listener(kListenPort, db);
    return EXIT_SUCCESS;
}
