#pragma once

#include "hta/secret_scalar.hpp"

#include <cstdint>
#include <vector>

namespace hta {
// Research prototype only. mcl does not provide verified constant-time secret operations.
// Do not use these operations with secrets exposed to timing or cache observers.
SecretScalar secret_scalar_add(const SecretScalar &left, const SecretScalar &right);
SecretScalar secret_scalar_subtract(const SecretScalar &left, const SecretScalar &right);
SecretScalar secret_scalar_multiply(const SecretScalar &left, const SecretScalar &right);
std::vector<std::uint8_t> secret_generator_multiply(const SecretScalar &scalar);
std::vector<std::uint8_t> secret_point_multiply(const std::vector<std::uint8_t> &point,
                                                const SecretScalar &scalar);
std::vector<std::uint8_t> secret_msm(const std::vector<std::vector<std::uint8_t>> &points,
                                     const std::vector<SecretScalar> &scalars);
} // namespace hta
