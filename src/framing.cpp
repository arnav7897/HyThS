#include "hta/framing.hpp"

#include <limits>
#include <stdexcept>

namespace hta {
std::vector<std::uint8_t> frame(std::uint8_t tag, const std::vector<std::uint8_t>& payload) {
    if (tag < 1 || tag > 6) throw std::invalid_argument("unknown frame tag");
    if (payload.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::length_error("frame payload exceeds 32-bit length");
    const auto size = static_cast<std::uint32_t>(payload.size());
    std::vector<std::uint8_t> result{tag, static_cast<std::uint8_t>(size >> 24),
                                     static_cast<std::uint8_t>(size >> 16),
                                     static_cast<std::uint8_t>(size >> 8),
                                     static_cast<std::uint8_t>(size)};
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}
}
