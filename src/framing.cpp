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

std::optional<FrameView> read_frame(const std::vector<std::uint8_t>& input, std::size_t offset,
                                    std::uint8_t expected_tag, std::size_t max_payload) noexcept {
    if (expected_tag < 1 || expected_tag > 6 || offset > input.size() ||
        input.size() - offset < 5 || input[offset] != expected_tag) return std::nullopt;
    std::uint32_t size = 0;
    for (std::size_t i = 1; i <= 4; ++i) size = (size << 8) | input[offset + i];
    const std::size_t start = offset + 5;
    if (size > max_payload || size > input.size() - start) return std::nullopt;
    return FrameView{start, size, start + size};
}
}
