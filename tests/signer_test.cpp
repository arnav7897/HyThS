#include "hta/signer.hpp"

#include "hta/framing.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"

#include <array>
#include <atomic>
#include <cstdlib>
#include <thread>

namespace {
hta::SecretScalar secret(std::uint8_t value) {
    std::array<std::uint8_t, 32> encoded{};
    encoded.back() = value;
    return hta::SecretScalar::from_canonical(encoded);
}

hta::PublicBytes point_field(const hta::PublicBytes &point) { return hta::frame(4, point); }

hta::PublicBytes scalar_bytes(const hta::SecretScalar &scalar) {
    return {scalar.bytes().begin(), scalar.bytes().end()};
}

hta::PublicBytes add_points(const hta::PublicBytes &a, const hta::PublicBytes &b) {
    const auto result = hta::public_point_add(a, b);
    return result ? *result : hta::PublicBytes{};
}

hta::PublicBytes session_context(const hta::PublicBytes &sid, const hta::Roster &roster,
                                 const hta::PublicBytes &message,
                                 const hta::PublicBytes &masked_key) {
    hta::PublicBytes subset_payload = hta::frame_integer(1);
    const auto index2 = hta::frame_integer(2);
    subset_payload.insert(subset_payload.end(), index2.begin(), index2.end());
    const auto subset = hta::transcript("SUBSET", {hta::frame(6, subset_payload)});
    const hta::PublicBytes digest(roster.digest.begin(), roster.digest.end());
    return hta::transcript("CTX", {hta::frame(2, sid), hta::frame(2, digest),
                                    hta::frame_integer(2), hta::frame(2, message),
                                    point_field(masked_key), hta::frame(2, subset)});
}

hta::PublicBytes signature_challenge(const hta::Roster &roster,
                                     const hta::PublicBytes &masked_key,
                                     const hta::PublicBytes &nonce,
                                     const hta::PublicBytes &message) {
    const hta::PublicBytes digest(roster.digest.begin(), roster.digest.end());
    const auto input = hta::transcript("SIG", {hta::frame(2, digest), point_field(masked_key),
                                                 hta::frame_integer(2), point_field(nonce),
                                                 hta::frame(2, message)});
    const auto value = hta::scalar_challenge(input, true);
    return {value.begin(), value.end()};
}
} // namespace

int main() {
    const hta::PublicBytes registry{'r', 'e', 'g'};
    const auto registration1 = hta::create_registration(secret(7), 1, registry);
    const auto registration2 = hta::create_registration(secret(11), 2, registry);
    const auto roster = hta::build_roster({registration1, registration2}, registry);
    if (!roster)
        return EXIT_FAILURE;

    const auto xi = secret(13);
    const auto masked_key = add_points(
        add_points(roster->public_keys[0], roster->public_keys[1]),
        hta::secret_generator_multiply(xi));
    const hta::PublicBytes sid{'s', 'e', 's', 's', 'i', 'o', 'n', '1'};
    const hta::PublicBytes message{'m', 's', 'g'};
    hta::Signer signer1(1, secret(7));
    hta::Signer signer2(2, secret(11));
    const auto first = signer1.round1(*roster, sid, 2, message, masked_key, {1, 2});
    const auto second = signer2.round1(*roster, sid, 2, message, masked_key, {1, 2});
    if (!first || !second || signer1.round1(*roster, sid, 2, message, masked_key, {1, 2}))
        return EXIT_FAILURE;

    const auto aggregate_first = add_points(first->first, second->first);
    const auto aggregate_second = add_points(first->second, second->second);
    const std::vector<hta::PublicBytes> beta_fields{
        hta::frame(2, session_context(sid, *roster, message, masked_key)),
        point_field(aggregate_first), point_field(aggregate_second)};
    const auto beta_input = hta::transcript("NON", beta_fields);
    const auto beta_array = hta::scalar_challenge(beta_input, false);
    const hta::PublicBytes beta(beta_array.begin(), beta_array.end());
    const auto weighted_second = hta::public_point_multiply(aggregate_second, beta);
    const auto nonce = weighted_second ? add_points(aggregate_first, *weighted_second)
                                       : hta::PublicBytes{};
    const auto c = signature_challenge(*roster, masked_key, nonce, message);
    const auto response1 = signer1.round2(sid, aggregate_first, aggregate_second);
    const auto response2 = signer2.round2(sid, aggregate_first, aggregate_second);
    if (!response1 || !response2 || signer1.round2(sid, aggregate_first, aggregate_second))
        return EXIT_FAILURE;

    const auto aggregate_response = hta::public_scalar_add(*response1, *response2);
    const auto tweak_response = hta::public_scalar_multiply(c, scalar_bytes(xi));
    const auto final_response = aggregate_response && tweak_response
                                    ? hta::public_scalar_add(*aggregate_response, *tweak_response)
                                    : std::nullopt;
    const auto left = final_response ? hta::public_generator_multiply(*final_response) : std::nullopt;
    const auto challenge_key = hta::public_point_multiply(masked_key, c);
    const auto right = challenge_key ? hta::public_point_add(nonce, *challenge_key) : std::nullopt;
    if (!left || !right || *left != *right)
        return EXIT_FAILURE;

    hta::Signer burn_on_abort(1, secret(7));
    const hta::PublicBytes invalid_sid{'b', 'a', 'd'};
    if (!burn_on_abort.round1(*roster, invalid_sid, 1, message, masked_key, {1}) ||
        burn_on_abort.round2(invalid_sid, {0}, aggregate_second) ||
        burn_on_abort.round2(invalid_sid, aggregate_first, aggregate_second))
        return EXIT_FAILURE;

    hta::Signer concurrent(1, secret(7));
    const hta::PublicBytes concurrent_sid{'c', 'o', 'n', 'c'};
    std::atomic<unsigned> accepted{0};
    auto reserve = [&] {
        if (concurrent.round1(*roster, concurrent_sid, 1, message, masked_key, {1}))
            ++accepted;
    };
    std::thread first_attempt(reserve);
    std::thread second_attempt(reserve);
    first_attempt.join();
    second_attempt.join();
    if (accepted != 1)
        return EXIT_FAILURE;

    hta::Signer parallel_sessions(1, secret(7));
    std::atomic<unsigned> parallel_accepted{0};
    auto reserve_distinct = [&](hta::PublicBytes distinct_sid) {
        if (parallel_sessions.round1(*roster, distinct_sid, 1, message, masked_key, {1}))
            ++parallel_accepted;
    };
    std::thread distinct_first(reserve_distinct, hta::PublicBytes{'a'});
    std::thread distinct_second(reserve_distinct, hta::PublicBytes{'b'});
    distinct_first.join();
    distinct_second.join();
    if (parallel_accepted != 2)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
