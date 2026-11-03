#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hta {
// RFC 9380 expand_message_xmd with SHA-256; inputs are public bytes.
// Rejects output lengths outside 1..8160 and hashes DSTs longer than 255 bytes.
std::vector<std::uint8_t> expand_message_xmd_sha256(const std::vector<std::uint8_t> &message,
                                                    const std::vector<std::uint8_t> &dst,
                                                    std::size_t output_length);
} // namespace hta
