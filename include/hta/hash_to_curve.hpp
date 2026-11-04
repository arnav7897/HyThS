#pragma once

#include <cstdint>
#include <vector>

namespace hta {
// RFC 9380 secp256k1_XMD:SHA-256_SSWU_RO_ hash_to_curve for public messages.
// Output uses SEC 1 compressed encoding, with 00 reserved for identity.
std::vector<std::uint8_t> hash_to_curve_secp256k1(const std::vector<std::uint8_t> &message);
std::vector<std::uint8_t> hash_to_curve_secp256k1(const std::vector<std::uint8_t> &message,
                                                  const std::vector<std::uint8_t> &dst);
} // namespace hta
