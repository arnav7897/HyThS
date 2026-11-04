#include "hta/secret_scalar.hpp"

#include <algorithm>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace hta {
namespace {
constexpr std::array<std::uint8_t, 32> order = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

bool less_than_order(const std::array<std::uint8_t, 32> &value) noexcept {
    std::uint32_t less = 0;
    std::uint32_t greater = 0;
    for (std::size_t i = 0; i < value.size(); ++i) {
        const std::uint32_t undecided = 1U ^ (less | greater);
        const std::uint32_t current = value[i];
        const std::uint32_t bound = order[i];
        less |= undecided & ((current - bound) >> 31);
        greater |= undecided & ((bound - current) >> 31);
    }
    return less == 1U;
}

bool nonzero(const std::array<std::uint8_t, 32> &value) noexcept {
    std::uint8_t combined = 0;
    for (const auto byte : value)
        combined |= byte;
    return combined != 0;
}
} // namespace

SecretScalar::SecretScalar(const std::array<std::uint8_t, 32> &bytes) noexcept : bytes_(bytes) {}

SecretScalar::SecretScalar(SecretScalar &&other) noexcept : bytes_(other.bytes_) {
    OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
}

SecretScalar &SecretScalar::operator=(SecretScalar &&other) noexcept {
    if (this != &other) {
        OPENSSL_cleanse(bytes_.data(), bytes_.size());
        bytes_ = other.bytes_;
        OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
    }
    return *this;
}

SecretScalar::~SecretScalar() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

bool SecretScalar::valid() const noexcept { return nonzero(bytes_) && less_than_order(bytes_); }

SecretScalar random_secret_scalar() {
    constexpr unsigned int maximum_attempts = 128;
    for (unsigned int attempt = 0; attempt < maximum_attempts; ++attempt) {
        std::array<std::uint8_t, 32> candidate{};
        if (RAND_priv_bytes(candidate.data(), static_cast<int>(candidate.size())) != 1) {
            OPENSSL_cleanse(candidate.data(), candidate.size());
            throw std::runtime_error("OpenSSL private random generator failed");
        }
        if (nonzero(candidate) && less_than_order(candidate)) {
            SecretScalar result(candidate);
            OPENSSL_cleanse(candidate.data(), candidate.size());
            return result;
        }
        OPENSSL_cleanse(candidate.data(), candidate.size());
    }
    throw std::runtime_error("scalar rejection limit reached");
}
} // namespace hta
