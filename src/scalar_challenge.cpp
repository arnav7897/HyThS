#include "hta/scalar_challenge.hpp"

#include "hta/framing.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include <openssl/evp.h>

namespace hta {
std::array<std::uint8_t, 32> scalar_challenge(const std::vector<std::uint8_t> &transcript_bytes,
                                              bool nonzero) {
    const auto framed = frame(2, transcript_bytes);
    for (std::uint64_t counter = 0;; ++counter) {
        const auto input = transcript("SCALAR", {framed, frame_integer(counter)});
        std::array<std::uint8_t, 32> digest{};
        std::size_t length = 0;
        if (EVP_Q_digest(nullptr, "SHA256", nullptr, input.data(), input.size(), digest.data(),
                         &length) != 1 ||
            length != digest.size())
            throw std::runtime_error("SHA-256 failed");
        const std::vector<std::uint8_t> encoded(digest.begin(), digest.end());
        const bool is_zero =
            std::all_of(digest.begin(), digest.end(), [](auto byte) { return byte == 0; });
        if (is_canonical_scalar(encoded) && (!nonzero || !is_zero))
            return digest;
        if (counter == std::numeric_limits<std::uint64_t>::max())
            throw std::overflow_error("scalar challenge counter exhausted");
    }
}
} // namespace hta
