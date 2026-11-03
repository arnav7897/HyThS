#pragma once

#include <cstdint>
#include <optional>

namespace hta {
struct Dimensions { std::uint32_t ell; std::uint32_t N; std::uint32_t generators; };
// Draft secp256k1 suite, audit v5 equations (1) and (2).
std::optional<Dimensions> dimensions(std::uint32_t n, std::uint32_t threshold) noexcept;
}
