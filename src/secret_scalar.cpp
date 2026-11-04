#include "hta/secret_scalar.hpp"
#include "secret_scalar_test.hpp"

#include "hta/framing.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace hta {
namespace {
thread_local const testing::RandomBytes *testing_random_bytes = nullptr;
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

template <typename RandomBytes>
std::array<std::uint8_t, 32> sample(RandomBytes &&random_bytes, bool require_nonzero) {
    constexpr unsigned int maximum_attempts = 128;
    for (unsigned int attempt = 0; attempt < maximum_attempts; ++attempt) {
        std::array<std::uint8_t, 32> candidate{};
        if (random_bytes(candidate.data(), static_cast<int>(candidate.size())) != 1) {
            OPENSSL_cleanse(candidate.data(), candidate.size());
            throw std::runtime_error("OpenSSL private random generator failed");
        }
        if ((!require_nonzero || nonzero(candidate)) && less_than_order(candidate)) {
            auto result = candidate;
            OPENSSL_cleanse(candidate.data(), candidate.size());
            return result;
        }
        OPENSSL_cleanse(candidate.data(), candidate.size());
    }
    throw std::runtime_error("scalar rejection limit reached");
}
} // namespace

SecretScalar::SecretScalar(const std::array<std::uint8_t, 32> &bytes) noexcept : bytes_(bytes) {}

SecretScalar::SecretScalar(SecretScalar &&other) noexcept
    : bytes_(other.bytes_), initialized_(other.initialized_) {
    OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
    other.initialized_ = false;
}

SecretScalar &SecretScalar::operator=(SecretScalar &&other) noexcept {
    if (this != &other) {
        OPENSSL_cleanse(bytes_.data(), bytes_.size());
        bytes_ = other.bytes_;
        initialized_ = other.initialized_;
        OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
        other.initialized_ = false;
    }
    return *this;
}

SecretScalar::~SecretScalar() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }

bool SecretScalar::valid(bool require_nonzero) const noexcept {
    return initialized_ && less_than_order(bytes_) && (!require_nonzero || nonzero(bytes_));
}

SecretScalar SecretScalar::from_canonical(const std::array<std::uint8_t, 32> &bytes) {
    const std::vector<std::uint8_t> encoded(bytes.begin(), bytes.end());
    if (!is_canonical_scalar(encoded))
        throw std::invalid_argument("secret scalar encoding is not canonical");
    return SecretScalar(bytes);
}

SecretScalar random_secret_scalar() {
    auto candidate = testing_random_bytes
                         ? sample(*testing_random_bytes, true)
                         : sample([](std::uint8_t *output,
                                     int length) { return RAND_priv_bytes(output, length); },
                                  true);
    SecretScalar result(candidate);
    OPENSSL_cleanse(candidate.data(), candidate.size());
    return result;
}

SecretScalar random_secret_scalar_allow_zero() {
    auto candidate = testing_random_bytes
                         ? sample(*testing_random_bytes, false)
                         : sample([](std::uint8_t *output,
                                     int length) { return RAND_priv_bytes(output, length); },
                                  false);
    SecretScalar result(candidate);
    OPENSSL_cleanse(candidate.data(), candidate.size());
    return result;
}

SecretScalar testing::random_secret_scalar_with_rng(const RandomBytes &random_bytes) {
    auto candidate = sample(random_bytes, true);
    SecretScalar result(candidate);
    OPENSSL_cleanse(candidate.data(), candidate.size());
    return result;
}

SecretScalar testing::random_secret_scalar_allow_zero_with_rng(const RandomBytes &random_bytes) {
    auto candidate = sample(random_bytes, false);
    SecretScalar result(candidate);
    OPENSSL_cleanse(candidate.data(), candidate.size());
    return result;
}

testing::ScopedRandomBytes::ScopedRandomBytes(RandomBytes random_bytes)
    : random_bytes_(std::move(random_bytes)), previous_(testing_random_bytes) {
    if (!random_bytes_)
        throw std::invalid_argument("test random source is empty");
    testing_random_bytes = &random_bytes_;
}

testing::ScopedRandomBytes::~ScopedRandomBytes() { testing_random_bytes = previous_; }
} // namespace hta
