#include "hta/registration.hpp"

#include "hta/framing.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secret_group.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

#include <openssl/evp.h>

namespace hta {
namespace {
std::vector<std::uint8_t> point_field(const PublicBytes &point) { return frame(4, point); }

std::vector<std::uint8_t> pop_context(const PublicBytes &registry_id) {
    return transcript("POPCTX", {frame(2, registry_id)});
}

std::vector<std::uint8_t> pop_transcript(const Registration &registration,
                                         const PublicBytes &registry_id) {
    const auto context = pop_context(registry_id);
    return transcript("POP", {frame(2, context), frame_integer(registration.index),
                              point_field(registration.public_key),
                              point_field(registration.proof.commitment)});
}

bool valid_context(const PublicBytes &registry_id) {
    return !registry_id.empty() && registry_id.size() <= 1024 * 1024;
}

std::optional<std::array<std::uint8_t, 32>>
roster_digest(const std::vector<PublicBytes> &public_keys) {
    std::vector<std::uint8_t> vector_payload;
    for (const auto &key : public_keys) {
        const auto field = point_field(key);
        vector_payload.insert(vector_payload.end(), field.begin(), field.end());
    }
    const auto input =
        transcript("ROSTER", {frame_integer(public_keys.size()), frame(6, vector_payload)});
    std::array<std::uint8_t, 32> digest{};
    std::size_t length = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, input.data(), input.size(), digest.data(),
                     &length) != 1 ||
        length != digest.size())
        return std::nullopt;
    return digest;
}
} // namespace

Registration create_registration(const SecretScalar &secret_key, std::uint64_t index,
                                 const PublicBytes &registry_id) {
    if (!secret_key.valid() || index == 0 || !valid_context(registry_id))
        throw std::invalid_argument("invalid registration input");
    Registration result{index, secret_generator_multiply(secret_key), {}};
    auto nonce = random_secret_scalar();
    result.proof.commitment = secret_generator_multiply(nonce);
    const auto challenge = scalar_challenge(pop_transcript(result, registry_id), false);
    auto challenge_scalar = SecretScalar::from_canonical(challenge);
    auto product = secret_scalar_multiply(challenge_scalar, secret_key);
    auto response = secret_scalar_add(nonce, product);
    result.proof.response.assign(response.bytes().begin(), response.bytes().end());
    return result;
}

bool verify_registration(const Registration &registration, const PublicBytes &registry_id) {
    if (!valid_context(registry_id) || registration.index == 0 ||
        !valid_public_point(registration.public_key, false) ||
        !valid_public_point(registration.proof.commitment, false) ||
        !valid_public_scalar(registration.proof.response))
        return false;
    const auto challenge = scalar_challenge(pop_transcript(registration, registry_id), false);
    const PublicBytes challenge_bytes(challenge.begin(), challenge.end());
    const auto left = public_generator_multiply(registration.proof.response);
    const auto challenge_key = public_point_multiply(registration.public_key, challenge_bytes);
    if (!left || !challenge_key)
        return false;
    const auto right = public_point_add(registration.proof.commitment, *challenge_key);
    return right && *left == *right;
}

std::optional<Roster> build_roster(const std::vector<Registration> &registrations,
                                   const PublicBytes &registry_id) {
    if (!valid_context(registry_id) || registrations.empty() || registrations.size() > 65535)
        return std::nullopt;
    std::set<PublicBytes> seen;
    Roster roster{{}, {}};
    roster.public_keys.reserve(registrations.size());
    for (std::size_t i = 0; i < registrations.size(); ++i) {
        const auto &registration = registrations[i];
        if (registration.index != i + 1 || !seen.insert(registration.public_key).second ||
            !verify_registration(registration, registry_id))
            return std::nullopt;
        roster.public_keys.push_back(registration.public_key);
    }
    const auto digest = roster_digest(roster.public_keys);
    if (!digest)
        return std::nullopt;
    roster.digest = *digest;
    return roster;
}
} // namespace hta
