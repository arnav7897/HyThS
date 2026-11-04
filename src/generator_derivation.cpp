#include "hta/generator_derivation.hpp"

#include "hta/framing.hpp"
#include "hta/hash_to_curve.hpp"

#include <limits>
#include <stdexcept>

namespace hta {
namespace {
std::vector<std::uint8_t> framed_bytes(const std::vector<std::uint8_t> &value) {
    return frame(2, value);
}

std::vector<std::uint8_t> generator_input(const PublicBytes &context, std::uint32_t N,
                                          std::uint32_t index) {
    const std::string suite = "HTA-secp256k1-v1";
    const PublicBytes suite_bytes(suite.begin(), suite.end());
    return transcript("GEN", {framed_bytes(suite_bytes), framed_bytes(context), frame_integer(N),
                              frame_integer(index)});
}
} // namespace

PublicBytes derive_generator_secp256k1(const PublicBytes &context, std::uint32_t N,
                                       std::uint32_t index) {
    // N <= 65552 follows the frozen suite's n <= 65535 policy and ell = bit_length(n).
    constexpr std::uint32_t max_N = 65552;
    constexpr std::size_t max_context_bytes = 1024 * 1024;
    if (N == 0 || N > max_N || index == 0 || index > 2 * N + 1 ||
        context.size() > max_context_bytes)
        throw std::invalid_argument("invalid generator derivation parameters");

    static const PublicBytes dst{'H', 'T', 'A', '-', 'v', '1', '-', 's', 'e', 'c', 'p',
                                 '2', '5', '6', 'k', '1', '-', 'H', 'g', 'e', 'n'};
    const auto original = generator_input(context, N, index);
    auto point = hash_to_curve_secp256k1(original, dst);
    if (point != PublicBytes{0})
        return point;

    for (std::uint64_t counter = 1;; ++counter) {
        const auto retry = transcript("GEN-RETRY", {frame(2, original), frame_integer(counter)});
        point = hash_to_curve_secp256k1(retry, dst);
        if (point != PublicBytes{0})
            return point;
        if (counter == std::numeric_limits<std::uint64_t>::max())
            throw std::overflow_error("generator retry counter exhausted");
    }
}
} // namespace hta
