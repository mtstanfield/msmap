#include "parser.h"
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  (void)msmap::parse_log(std::string_view{reinterpret_cast<const char*>(data), size});
  return 0;
}