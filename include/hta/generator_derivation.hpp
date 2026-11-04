#pragma once

#include "hta/secp256k1_public.hpp"

#include <cstdint>

namespace hta {
// Derive one protocol generator under caller-authenticated context and N.
// Context is pinned outside this function; this primitive does not authenticate it.
PublicBytes derive_generator_secp256k1(const PublicBytes &context, std::uint32_t N,
                                       std::uint32_t index);
} // namespace hta
