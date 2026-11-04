#pragma once

#include "hta/secp256k1_public.hpp"
#include "hta/secret_scalar.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace hta {
struct ProofOfPossession {
    PublicBytes commitment;
    PublicBytes response;
};

struct Registration {
    std::uint64_t index;
    PublicBytes public_key;
    ProofOfPossession proof;
};

struct Roster {
    std::vector<PublicBytes> public_keys;
    std::array<std::uint8_t, 32> digest;
};

// Audit v5 §3, equation (4), instantiated with the frozen HTA suite transcript.
Registration create_registration(const SecretScalar &secret_key, std::uint64_t index,
                                 const PublicBytes &registry_id);
bool verify_registration(const Registration &registration, const PublicBytes &registry_id);
std::optional<Roster> build_roster(const std::vector<Registration> &registrations,
                                   const PublicBytes &registry_id);
} // namespace hta
