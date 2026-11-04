#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace hta {
// RFC 9380 secp256k1 hash_to_field, for public messages. Outputs big-endian Fp elements.
// Rejects counts outside 1..170, the limit imposed by SHA-256 XMD output length.
std::vector<std::array<std::uint8_t, 32>>
hash_to_field_secp256k1(const std::vector<std::uint8_t> &message,
                        const std::vector<std::uint8_t> &dst, std::size_t count);
} // namespace hta
