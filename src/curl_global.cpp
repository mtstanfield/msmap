#include "curl_global.h"

#include <curl/curl.h>

#include <mutex>

namespace msmap {

bool ensure_curl_global_init() noexcept
{
    static std::once_flag init_once;
    static bool init_ok = false; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    std::call_once(init_once, []() noexcept {
        init_ok = (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
    });

    return init_ok;
}

} // namespace msmap
