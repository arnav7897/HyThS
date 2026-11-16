#pragma once

#include <cstdint>
#include <optional>

namespace hta {
struct Dimensions {
    std::uint32_t ell;
    std::uint32_t N;
    std::uint32_t generators;
    std::uint32_t kappa;
};
// ASIACCS27 secp256k1 suite, equations (3.1) and (3.2).
std::optional<Dimensions> dimensions(std::uint32_t n, std::uint32_t threshold) noexcept;
} // namespace hta
