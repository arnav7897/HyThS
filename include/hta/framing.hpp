#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace hta {
// Draft suite framing only; callers validate payloads and enforce resource limits.
std::vector<std::uint8_t> frame(std::uint8_t tag, const std::vector<std::uint8_t>& payload);
std::vector<std::uint8_t> frame_integer(std::uint64_t value);

struct FrameView { std::size_t payload_offset; std::size_t payload_size; std::size_t next_offset; };
// Returns a view into input; caller validates the payload and any remaining bytes.
std::optional<FrameView> read_frame(const std::vector<std::uint8_t>& input, std::size_t offset,
                                    std::uint8_t expected_tag, std::size_t max_payload) noexcept;
}
