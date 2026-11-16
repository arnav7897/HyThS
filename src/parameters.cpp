#include "hta/parameters.hpp"

namespace hta {
std::optional<Dimensions> dimensions(std::uint32_t n, std::uint32_t threshold) noexcept {
    if (n == 0 || n > 65535 || threshold == 0 || threshold > n)
        return std::nullopt;
    std::uint32_t ell = 0;
    for (auto value = n; value != 0; value >>= 1)
        ++ell;
    std::uint32_t kappa = 0;
    for (auto value = n + ell - 1; value != 0; value >>= 1)
        ++kappa;
    const std::uint32_t N = std::uint32_t{1} << kappa;
    // The n bound gives kappa <= 17, so all dimension arithmetic fits uint32_t.
    // secp256k1's order exceeds max(N + 1, n + 2^ell - 1, 3), equation (3.2).
    return Dimensions{ell, N, 2 * N + 3, kappa};
}
} // namespace hta
