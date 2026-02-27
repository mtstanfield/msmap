// msmap – Mikrotik Firewall Log Viewer

#include "listener.h"

#include <cstdlib>

namespace {

constexpr int kListenPort{5140};

} // namespace

int main() {
    msmap::run_listener(kListenPort);
    return EXIT_SUCCESS;
}
