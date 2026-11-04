#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

namespace hta::testing {
using ChallengeHash =
    std::function<std::array<std::uint8_t, 32>(const std::vector<std::uint8_t> &)>;
std::array<std::uint8_t, 32>
scalar_challenge_with_hash(const std::vector<std::uint8_t> &transcript_bytes, bool nonzero,
                           const ChallengeHash &hash, std::uint64_t first_counter = 0);
} // namespace hta::testing
