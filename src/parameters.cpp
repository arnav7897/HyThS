#include "hta/parameters.hpp"

namespace hta {
std::optional<Dimensions> dimensions(std::uint32_t n, std::uint32_t threshold) noexcept {
    if (n == 0 || n > 65535 || threshold == 0 || threshold > n)
        return std::nullopt;
    std::uint32_t ell = 0;
    for (auto value = n; value != 0; value >>= 1)
        ++ell;
    const auto N = n + ell + 1;
    // For n <= 65535, secp256k1's 256-bit order exceeds every bound in equation (2).
    return Dimensions{ell, N, 2 * N + 1};
}
} // namespace hta
