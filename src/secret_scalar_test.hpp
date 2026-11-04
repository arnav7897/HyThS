#pragma once

#include "hta/secret_scalar.hpp"

namespace hta::testing {
// Test-only thread-local entropy override for deterministic end-to-end vectors.
class ScopedRandomBytes final {
  public:
    explicit ScopedRandomBytes(RandomBytes random_bytes);
    ScopedRandomBytes(const ScopedRandomBytes &) = delete;
    ScopedRandomBytes &operator=(const ScopedRandomBytes &) = delete;
    ~ScopedRandomBytes();

  private:
    RandomBytes random_bytes_;
    const RandomBytes *previous_;
};
} // namespace hta::testing
