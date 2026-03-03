#include "ip_intel_cache.h"

#include <arpa/inet.h>
#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace msmap {

namespace {

struct IpNet {
    int                    family{AF_UNSPEC};
    std::array<std::uint8_t, 16> bytes{};
    std::uint8_t           prefix_len{0};
};

struct SnapshotState {
    bool              tor_loaded{false};
    bool              drop_loaded{false};
    std::vector<IpNet> tor_nets;
    std::vector<IpNet> drop_nets;
};

// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
std::mutex g_snapshot_mutex;
// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
SnapshotState g_snapshot_state;

std::size_t curl_write_cb(const char* ptr, std::size_t /*size*/,
                          std::size_t nmemb, void* userdata) noexcept
{
    auto* const buf = static_cast<std::string*>(userdata);
    buf->append(ptr, nmemb);
    return nmemb;
}

std::optional<std::string> fetch_body(const std::string& url) noexcept
{
    CURL* const curl = curl_easy_init();
    if (curl == nullptr) {
        return std::nullopt;
    }
    struct CurlCloser {
        void operator()(CURL* handle) const noexcept { curl_easy_cleanup(handle); }
    };
    const std::unique_ptr<CURL, CurlCloser> guard{curl};

    std::string body;
    body.reserve(4096);
    (void)curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    (void)curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    (void)curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    (void)curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    (void)curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    const CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::clog << "[WARN] IpIntelCache: curl " << url
                  << ": " << curl_easy_strerror(res) << '\n';
        return std::nullopt;
    }
    long http_code{0};
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        std::clog << "[WARN] IpIntelCache: HTTP " << http_code
                  << " for " << url << '\n';
        return std::nullopt;
    }
    return body;
}

std::string trim(std::string_view raw)
{
    const auto first = raw.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = raw.find_last_not_of(" \t\r\n");
    return std::string{raw.substr(first, last - first + 1)};
}

std::optional<IpNet> parse_net_token(std::string_view token) noexcept
{
    const std::string value = trim(token);
    if (value.empty()) {
        return std::nullopt;
    }

    const auto slash = value.find('/');
    const std::string ip_part = value.substr(0, slash);
    auto parse_prefix = [&](int max_bits, int default_bits) noexcept -> std::optional<std::uint8_t> {
        if (slash == std::string::npos) {
            return static_cast<std::uint8_t>(default_bits);
        }
        const std::string raw_prefix = value.substr(slash + 1);
        if (raw_prefix.empty()) {
            return std::nullopt;
        }
        char* end = nullptr;
        const long parsed = std::strtol(raw_prefix.c_str(), &end, 10);
        if (*end != '\0' || parsed < 0 || parsed > max_bits) {
            return std::nullopt;
        }
        return static_cast<std::uint8_t>(parsed);
    };

    IpNet net;
    if (inet_pton(AF_INET, ip_part.c_str(), net.bytes.data()) == 1) {
        net.family = AF_INET;
        const auto prefix = parse_prefix(32, 32);
        if (!prefix.has_value()) {
            return std::nullopt;
        }
        net.prefix_len = *prefix;
        return net;
    }
    if (inet_pton(AF_INET6, ip_part.c_str(), net.bytes.data()) == 1) {
        net.family = AF_INET6;
        const auto prefix = parse_prefix(128, 128);
        if (!prefix.has_value()) {
            return std::nullopt;
        }
        net.prefix_len = *prefix;
        return net;
    }
    return std::nullopt;
}

bool ip_in_net(const std::string& ip, const IpNet& net) noexcept
{
    std::array<std::uint8_t, 16> candidate{};
    if (inet_pton(net.family, ip.c_str(), candidate.data()) != 1) {
        return false;
    }

    const int full_bytes = net.prefix_len / 8;
    const int rem_bits = net.prefix_len % 8;
    if (!std::equal(net.bytes.begin(), net.bytes.begin() + full_bytes, candidate.begin())) {
        return false;
    }
    if (rem_bits == 0) {
        return true;
    }

    const auto byte_index = static_cast<std::size_t>(full_bytes);
    const auto mask = static_cast<std::uint8_t>(0xFFU << (8 - rem_bits));
    return (net.bytes.at(byte_index) & mask) == (candidate.at(byte_index) & mask);
}

bool matches_any(const std::string& ip, const std::vector<IpNet>& nets) noexcept
{
    return std::any_of(nets.begin(), nets.end(), [&](const IpNet& net) noexcept {
        return ip_in_net(ip, net);
    });
}

std::vector<IpNet> parse_line_oriented_nets(std::string_view body)
{
    std::vector<IpNet> nets;
    std::size_t start = 0;
    while (start < body.size()) {
        const auto end = body.find('\n', start);
        const std::string line = trim(body.substr(
            start, end == std::string_view::npos ? body.size() - start : end - start));
        start = (end == std::string_view::npos) ? body.size() : end + 1;
        if (line.empty() || line.front() == '#') {
            continue;
        }
        const auto hash = line.find(';');
        const std::string token = trim(hash == std::string::npos
            ? std::string_view{line}
            : std::string_view{line}.substr(0, hash));
        if (const auto parsed = parse_net_token(token); parsed.has_value()) {
            nets.push_back(*parsed);
        }
    }
    return nets;
}

std::vector<IpNet> parse_drop_json(std::string_view body)
{
    std::vector<IpNet> nets;
    std::size_t start = 0;
    while (start < body.size()) {
        const auto open = body.find('"', start);
        if (open == std::string_view::npos) { break; }
        const auto close = body.find('"', open + 1);
        if (close == std::string_view::npos) { break; }
        const std::string_view token = body.substr(open + 1, close - open - 1);
        if (token.find('/') != std::string_view::npos) {
            if (const auto parsed = parse_net_token(token); parsed.has_value()) {
                nets.push_back(*parsed);
            }
        }
        start = close + 1;
    }
    return nets;
}

void replace_snapshot(std::vector<IpNet> nets,
                      bool& loaded_flag,
                      std::vector<IpNet>& target) noexcept
{
    target = std::move(nets);
    loaded_flag = true;
}

} // namespace

IpIntelCache::IpIntelCache(Database& db, const IpIntelSources& sources,
                           std::int64_t refresh_secs) noexcept
    : db_(db),
      tor_url_(sources.tor_url),
      drop_url_(sources.drop_url),
      refresh_secs_(refresh_secs > 0 ? refresh_secs : 21600),
      valid_(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK)
{
    if (!valid_) {
        std::clog << "[WARN] IpIntelCache: curl_global_init failed\n";
        return;
    }
    worker_thread_ = std::thread{[this]() noexcept { worker(); }};
}

IpIntelCache::~IpIntelCache() noexcept
{
    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        stop_ = true;
    }
    queue_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    if (valid_) {
        curl_global_cleanup();
    }
}

void IpIntelCache::submit(const std::string& ip) noexcept
{
    if (!valid_) { return; }
    {
        const std::lock_guard<std::mutex> lock{queue_mutex_};
        queue_.insert(ip);
    }
    queue_cv_.notify_one();
}

void IpIntelCache::worker() noexcept
{
    auto next_refresh = std::chrono::steady_clock::now();
    for (;;) {
        std::unordered_set<std::string> pending;

        {
            std::unique_lock<std::mutex> lock{queue_mutex_};
            queue_cv_.wait_until(lock, next_refresh, [this]() noexcept {
                return stop_ || !queue_.empty();
            });
            if (stop_) {
                return;
            }
            pending.swap(queue_);
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_refresh) {
            refresh_sources();
            refresh_known_ips();
            next_refresh = now + std::chrono::seconds(refresh_secs_);
        }
        if (!pending.empty()) {
            process_pending(pending);
        }
    }
}

void IpIntelCache::refresh_sources() noexcept
{
    if (!tor_url_.empty()) {
        if (const auto body = fetch_body(tor_url_); body.has_value()) {
            auto nets = parse_line_oriented_nets(*body);
            if (!nets.empty()) {
                const std::lock_guard<std::mutex> lock{g_snapshot_mutex};
                replace_snapshot(std::move(nets), g_snapshot_state.tor_loaded, g_snapshot_state.tor_nets);
            }
        }
    }

    if (!drop_url_.empty()) {
        if (const auto body = fetch_body(drop_url_); body.has_value()) {
            auto nets = parse_drop_json(*body);
            if (!nets.empty()) {
                const std::lock_guard<std::mutex> lock{g_snapshot_mutex};
                replace_snapshot(std::move(nets), g_snapshot_state.drop_loaded, g_snapshot_state.drop_nets);
            }
        }
    }

}

void IpIntelCache::refresh_known_ips() noexcept
{
    const auto ips = db_.distinct_source_ips();
    std::unordered_set<std::string> pending;
    pending.reserve(ips.size());
    for (const std::string& ip : ips) {
        pending.insert(ip);
    }
    process_pending(pending);
}

void IpIntelCache::process_pending(const std::unordered_set<std::string>& pending) noexcept
{
    for (const std::string& ip : pending) {
        (void)db_.upsert_ip_intel(ip, classify_ip(ip));
    }
}

IpIntel IpIntelCache::classify_ip(const std::string& ip) noexcept
{
    const std::lock_guard<std::mutex> lock{g_snapshot_mutex};
    IpIntel intel;
    if (g_snapshot_state.tor_loaded) {
        intel.tor_exit = matches_any(ip, g_snapshot_state.tor_nets);
    }
    if (g_snapshot_state.drop_loaded) {
        intel.spamhaus_drop = matches_any(ip, g_snapshot_state.drop_nets);
    }
    return intel;
}

} // namespace msmap
