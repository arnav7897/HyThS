#include "hta/framing.hpp"

#include <algorithm>
#include <array>
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

std::vector<std::uint8_t> frame_integer(std::uint64_t value) {
    std::vector<std::uint8_t> payload(8);
    for (std::size_t i = 8; i > 0; --i) {
        payload[i - 1] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
    return frame(3, payload);
}

bool is_canonical_scalar(const std::vector<std::uint8_t>& encoded) noexcept {
    constexpr std::array<std::uint8_t, 32> order{
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
    return encoded.size() == order.size() &&
           std::lexicographical_compare(encoded.begin(), encoded.end(), order.begin(), order.end());
}

std::vector<std::uint8_t> transcript(const std::string& label,
                                    const std::vector<std::vector<std::uint8_t>>& fields) {
    const std::string suite = "HTA-secp256k1-v1";
    auto payload = frame(2, {suite.begin(), suite.end()});
    const auto framed_label = frame(2, {label.begin(), label.end()});
    if (framed_label.size() > std::numeric_limits<std::uint32_t>::max() - payload.size())
        throw std::length_error("transcript too large");
    payload.insert(payload.end(), framed_label.begin(), framed_label.end());
    for (const auto& field : fields) {
        if (field.size() > std::numeric_limits<std::uint32_t>::max() - payload.size())
            throw std::length_error("transcript too large");
        payload.insert(payload.end(), field.begin(), field.end());
    }
    return frame(1, payload);
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
