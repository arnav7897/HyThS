#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

namespace hta {
class SecretScalar;
namespace testing {
using RandomBytes = std::function<int(std::uint8_t *, int)>;
SecretScalar random_secret_scalar_with_rng(const RandomBytes &random_bytes);
SecretScalar random_secret_scalar_allow_zero_with_rng(const RandomBytes &random_bytes);
} // namespace testing

// Move-only secret key material. Destructor and moves wipe owned bytes best-effort.
class SecretScalar final {
  public:
    SecretScalar(const SecretScalar &) = delete;
    SecretScalar &operator=(const SecretScalar &) = delete;
    SecretScalar(SecretScalar &&other) noexcept;
    SecretScalar &operator=(SecretScalar &&other) noexcept;
    ~SecretScalar();

    static SecretScalar from_canonical(const std::array<std::uint8_t, 32> &bytes);
    const std::array<std::uint8_t, 32> &bytes() const noexcept { return bytes_; }
    bool valid(bool require_nonzero = true) const noexcept;

  private:
    explicit SecretScalar(const std::array<std::uint8_t, 32> &bytes) noexcept;
    std::array<std::uint8_t, 32> bytes_{};
    friend SecretScalar random_secret_scalar();
    friend SecretScalar random_secret_scalar_allow_zero();
    friend SecretScalar testing::random_secret_scalar_with_rng(const testing::RandomBytes &);
    friend SecretScalar
    testing::random_secret_scalar_allow_zero_with_rng(const testing::RandomBytes &);
    friend SecretScalar secret_scalar_add(const SecretScalar &, const SecretScalar &);
    friend SecretScalar secret_scalar_subtract(const SecretScalar &, const SecretScalar &);
    friend SecretScalar secret_scalar_multiply(const SecretScalar &, const SecretScalar &);
    friend std::vector<std::uint8_t> secret_generator_multiply(const SecretScalar &);
    friend std::vector<std::uint8_t> secret_point_multiply(const std::vector<std::uint8_t> &,
                                                           const SecretScalar &);
    bool initialized_ = true;
};

// Uniformly samples a nonzero scalar modulo secp256k1 order using OpenSSL's private RNG.
SecretScalar random_secret_scalar();
// Uniformly samples a scalar from the full field, including zero.
SecretScalar random_secret_scalar_allow_zero();
} // namespace hta
