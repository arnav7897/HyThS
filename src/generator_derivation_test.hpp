#pragma once

#include "hta/secp256k1_public.hpp"

#include <cstdint>
#include <functional>

namespace hta::testing {
using GeneratorHash = std::function<PublicBytes(const PublicBytes &, const PublicBytes &)>;
PublicBytes derive_generator_with_hash(const PublicBytes &context, std::uint32_t N,
                                       std::uint32_t index, const GeneratorHash &hash,
                                       std::uint64_t first_retry_counter = 1);
} // namespace hta::testing
