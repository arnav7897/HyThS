#pragma once

#include <cstdint>
#include <vector>

namespace hta {
// Draft suite framing only; callers validate payloads and enforce resource limits.
std::vector<std::uint8_t> frame(std::uint8_t tag, const std::vector<std::uint8_t>& payload);
}
