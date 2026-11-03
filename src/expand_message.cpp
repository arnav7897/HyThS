#include "hta/expand_message.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

#include <openssl/evp.h>

namespace hta {
namespace {
using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;

Digest sha256(const Bytes &input) {
    Digest result{};
    std::size_t length = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, input.data(), input.size(), result.data(),
                     &length) != 1 ||
        length != result.size())
        throw std::runtime_error("SHA-256 failed");
    return result;
}
} // namespace

std::vector<std::uint8_t> expand_message_xmd_sha256(const Bytes &message, const Bytes &dst,
                                                    std::size_t output_length) {
    constexpr std::size_t max_length = 255 * 32;
    if (output_length == 0 || output_length > max_length)
        throw std::invalid_argument("XMD output length must be between 1 and 8160 bytes");

    Bytes domain = dst;
    if (domain.size() > 255) {
        const char prefix[] = "H2C-OVERSIZE-DST-";
        Bytes input(prefix, prefix + sizeof(prefix) - 1);
        input.insert(input.end(), domain.begin(), domain.end());
        const auto hashed = sha256(input);
        domain.assign(hashed.begin(), hashed.end());
    }
    domain.push_back(static_cast<std::uint8_t>(domain.size()));

    Bytes input(64, 0);
    input.insert(input.end(), message.begin(), message.end());
    input.push_back(static_cast<std::uint8_t>(output_length >> 8));
    input.push_back(static_cast<std::uint8_t>(output_length));
    input.push_back(0);
    input.insert(input.end(), domain.begin(), domain.end());
    const auto b0 = sha256(input);

    Digest previous{};
    Bytes output;
    output.reserve(output_length);
    const std::size_t blocks = (output_length + 31) / 32;
    for (std::size_t i = 1; i <= blocks; ++i) {
        input.clear();
        for (std::size_t j = 0; j < b0.size(); ++j)
            input.push_back(static_cast<std::uint8_t>(b0[j] ^ previous[j]));
        input.push_back(static_cast<std::uint8_t>(i));
        input.insert(input.end(), domain.begin(), domain.end());
        previous = sha256(input);
        const std::size_t count = std::min(previous.size(), output_length - output.size());
        output.insert(output.end(), previous.begin(), previous.begin() + count);
    }
    return output;
}
} // namespace hta
