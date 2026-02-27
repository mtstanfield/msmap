# Claude Instructions for This Project

## Development Environment

**Always use Docker for ALL development and build tasks.**
The host is Windows — never run cmake, clang, ninja, or any build tool directly
on the host.

### Dev image name: `msmap-dev`

```bash
# Build (re-run after any Dockerfile change)
docker build --target dev -t msmap-dev .
```

### Interactive dev shell

```bash
docker run -it --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev
```

### One-off commands (non-interactive)

```bash
docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev <command>
```

### Common command examples

```bash
# Configure (Debug)
docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev \
  cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_STANDARD=23 \
    -DCMAKE_CXX_EXTENSIONS=OFF \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# Build
docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev \
  ninja -C build msmap

# Tests
docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev \
  ninja -C build test

# clang-tidy
docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev \
  run-clang-tidy -p build

# cppcheck
docker run --rm -v "C:/Users/ms/projects/msmap:/workspace" msmap-dev \
  cppcheck --enable=style,performance,warning,portability --error-exitcode=1 src/
```

---

## Project: msmap

Mikrotik firewall log ingestion → SQLite → GeoIP/OSINT enrichment → web UI
(Leaflet.js world map). Self-contained binary, distroless runtime.

See `README.md` for full architecture and `PLAN.md` for the feature todo list.

---

## Key Conventions

- **Language**: C++23, `-std=c++23`, `-fno-exceptions` TBD
- **Compiler**: clang-18 (`CC=clang-18`, `CXX=clang++-18`)
- **Build**: CMake + Ninja; `cmake --build build` or `ninja -C build`
- **Dependencies**: apt packages only (no Conan, no CPM unless header-only lib needed)
  - `libmicrohttpd-dev`, `libsqlite3-dev`, `libmaxminddb-dev` — all in Debian bookworm
- **Static linking**: `-static-libgcc -static-libstdc++` + link app libs as `.a`
- **Runtime image**: `gcr.io/distroless/cc-debian12:nonroot`
- **Static analysis**: clang-tidy + cppcheck — both must be clean before commit
- **Warnings**: `-Wall -Wextra -Wpedantic -Werror` — treat all warnings as errors
- **Tests**: Catch2
- **Fuzzing**: libFuzzer on the syslog parser

---

## Log Format (confirmed)

Mikrotik router → rsyslog (UDP 514) → msmap (TCP 5140).

rsyslog reformats BSD timestamp to RFC 3339 before forwarding. msmap sees:

```
2026-02-27T08:14:23+00:00 router firewall,info FW_INPUT_NEW input: in:ether1 out:(unknown 0), connection-state:new src-mac bc:9a:8e:fb:12:f1, proto TCP (ACK), 172.234.31.140:65226->108.89.67.16:44258, len 52
```

**Protocol variants:**
- TCP: `proto TCP (FLAGS), IP:PORT->IP:PORT, len N`
- UDP: `proto UDP, IP:PORT->IP:PORT, len N`
- ICMP: `proto ICMP, IP->IP, len N`

**Parser approach**: hand-written linear tokenizer (not regex). Two phases:
1. RFC 3339 header strip (timestamp, hostname)
2. Mikrotik body: topic/level → optional rule name → chain keyword → key:value pairs → proto line

**Mikrotik router config (already applied):**
- NTP enabled (Google NTP servers)
- Timezone: UTC
- Log-prefix convention: `FW_<CHAIN>_<STATE>` (e.g. `FW_INPUT_NEW`, `FW_FWD_DROP`)

---

## Quality Gates (run before every commit)

1. `ninja -C build` — clean build, zero warnings
2. `run-clang-tidy -p build` — zero findings
3. `cppcheck ... src/` — zero findings
4. `ninja -C build test` — all tests pass
5. Update `FINDINGS.md` with any issues discovered; resolve before next feature

---

## Workflow Principles

- Slow, iterative development — one feature at a time, commit when working
- Issues discovered during development go into `FINDINGS.md`
- Review `FINDINGS.md` before starting each new feature
- Timestamps stored as UTC Unix epoch (int64); browser converts to local timezone
- All SQL via parameterized queries — no string concatenation ever
- All web assets embedded in binary via `xxd -i` CMake step
- No CDN, no external JS, no npm, no bundler
