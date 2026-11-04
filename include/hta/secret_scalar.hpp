#pragma once

#include <array>
#include <cstdint>

namespace hta {
// Move-only secret key material. Destructor and moves wipe owned bytes best-effort.
class SecretScalar final {
  public:
    SecretScalar(const SecretScalar &) = delete;
    SecretScalar &operator=(const SecretScalar &) = delete;
    SecretScalar(SecretScalar &&other) noexcept;
    SecretScalar &operator=(SecretScalar &&other) noexcept;
    ~SecretScalar();

    const std::array<std::uint8_t, 32> &bytes() const noexcept { return bytes_; }
    bool valid() const noexcept;

  private:
    explicit SecretScalar(const std::array<std::uint8_t, 32> &bytes) noexcept;
    std::array<std::uint8_t, 32> bytes_{};
    friend SecretScalar random_secret_scalar();
};

// Uniformly samples a nonzero scalar modulo secp256k1 order using OpenSSL's private RNG.
SecretScalar random_secret_scalar();
} // namespace hta
