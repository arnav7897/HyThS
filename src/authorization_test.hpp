#pragma once

#include "hta/authorization.hpp"

#include <functional>

namespace hta::testing {
using ChallengeProvider = std::function<PublicBytes(const PublicBytes &, bool)>;
bool verify_authorization_with_challenges(const Roster &roster,
                                         const PublicBytes &generator_context,
                                         std::uint32_t threshold, const PublicBytes &message,
                                         const PublicBytes &masked_key,
                                         const AuthorizationProof &proof,
                                         const ChallengeProvider &challenge);
} // namespace hta::testing
