#pragma once

#include "hta/coordinator.hpp"

namespace hta {
struct AuthorizationProof {
    PublicBytes A;
    PublicBytes S;
    PublicBytes Qs;
    PublicBytes T1;
    PublicBytes T2;
    std::vector<PublicBytes> vL;
    std::vector<PublicBytes> vR;
    PublicBytes t_hat;
    PublicBytes mu;
    PublicBytes tau_x;
};

struct FinalSignature {
    SchnorrSignature schnorr;
    AuthorizationProof authorization;
};

// Prototype Algorithm 2. Generator context and roster digest must be authenticated externally.
std::optional<AuthorizationProof>
prove_authorization(const Roster &roster, const PublicBytes &generator_context,
                    std::uint32_t threshold, const PublicBytes &message,
                    const PublicBytes &masked_key, const std::vector<std::uint8_t> &selectors,
                    const std::vector<std::uint8_t> &surplus_bits, SecretScalar tweak);

bool verify_authorization(const Roster &roster, const PublicBytes &generator_context,
                          std::uint32_t threshold, const PublicBytes &message,
                          const PublicBytes &masked_key, const AuthorizationProof &proof);

bool verify_signature(const Roster &roster, const PublicBytes &generator_context,
                      std::uint32_t threshold, const PublicBytes &message,
                      const FinalSignature &signature);
} // namespace hta
