#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace hta {
using PublicBytes = std::vector<std::uint8_t>;

// Research-only public-input operations. Not for signing keys or nonce scalars.
// mcl uses process-global curve state; do not initialize another mcl curve concurrently.
bool valid_public_scalar(const PublicBytes &encoded) noexcept;
bool valid_public_point(const PublicBytes &encoded, bool allow_identity);
std::optional<PublicBytes> public_scalar_add(const PublicBytes &left, const PublicBytes &right);
std::optional<PublicBytes> public_scalar_multiply(const PublicBytes &left,
                                                  const PublicBytes &right);
std::optional<PublicBytes> public_point_add(const PublicBytes &left, const PublicBytes &right);
std::optional<PublicBytes> public_point_multiply(const PublicBytes &point,
                                                 const PublicBytes &scalar);
std::optional<PublicBytes> public_generator_multiply(const PublicBytes &scalar);
std::optional<PublicBytes> public_msm(const std::vector<PublicBytes> &points,
                                      const std::vector<PublicBytes> &scalars);
} // namespace hta
