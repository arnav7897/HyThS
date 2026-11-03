#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace hta {
// Public transcript hash-to-scalar for the HTA-secp256k1-v1 research suite.
// When nonzero is true, reject zero as well as values at or above the group order.
std::array<std::uint8_t, 32> scalar_challenge(const std::vector<std::uint8_t> &transcript_bytes,
                                              bool nonzero);
} // namespace hta
