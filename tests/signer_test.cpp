#include "hta/coordinator.hpp"
#include "hta/authorization.hpp"
#include "hta/protocol_encoding.hpp"
#include "hta/signer.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdlib>
#include <stdexcept>
#include <thread>

namespace {
hta::SecretScalar secret(std::uint8_t value) {
    std::array<std::uint8_t, 32> encoded{};
    encoded.back() = value;
    return hta::SecretScalar::from_canonical(encoded);
}

} // namespace

int main() {
    const hta::PublicBytes registry{'r', 'e', 'g'};
    const auto registration1 = hta::create_registration(secret(7), 1, registry);
    const auto registration2 = hta::create_registration(secret(11), 2, registry);
    const auto roster = hta::build_roster({registration1, registration2}, registry);
    if (!roster)
        return EXIT_FAILURE;

    const hta::PublicBytes sid{'s', 'e', 's', 's', 'i', 'o', 'n', '1'};
    const hta::PublicBytes message{'m', 's', 'g'};
    auto coordinator = hta::CoordinatorSession::begin(*roster, sid, 2, message, {1, 2}, secret(13));
    if (!coordinator)
        return EXIT_FAILURE;
    const auto masked_key = coordinator->masked_key();
    hta::Signer signer1(1, secret(7));
    hta::Signer signer2(2, secret(11));
    const auto first = signer1.round1(*roster, sid, 2, message, masked_key, {1, 2});
    const auto second = signer2.round1(*roster, sid, 2, message, masked_key, {1, 2});
    if (!first || !second || signer1.round1(*roster, sid, 2, message, masked_key, {1, 2}))
        return EXIT_FAILURE;

    const auto aggregate = coordinator->collect_commitments({{1, *first}, {2, *second}});
    if (!aggregate)
        return EXIT_FAILURE;
    const auto response1 = signer1.round2(sid, aggregate->first, aggregate->second);
    const auto response2 = signer2.round2(sid, aggregate->first, aggregate->second);
    if (!response1 || !response2 || signer1.round2(sid, aggregate->first, aggregate->second) ||
        !coordinator->verify_partial_response(1, *response1) ||
        !coordinator->verify_partial_response(2, *response2))
        return EXIT_FAILURE;
    auto bad_partial = *response1;
    bad_partial.back() ^= 1;
    if (coordinator->verify_partial_response(1, bad_partial))
        return EXIT_FAILURE;
    const auto signature = coordinator->aggregate_responses({{1, *response1}, {2, *response2}});
    if (!signature || coordinator->aggregate_responses({{1, *response1}, {2, *response2}}))
        return EXIT_FAILURE;

    const hta::PublicBytes generator_context{'p', 'r', 'o', 'o', 'f', '-', 'c', 't', 'x'};
    const auto proof = hta::prove_authorization(*roster, generator_context, 2, message,
                                                signature->masked_key, {1, 1}, {0, 0}, secret(13));
    if (!proof)
        return EXIT_FAILURE;
    const hta::FinalSignature final_signature{*signature, *proof};
    if (!hta::verify_signature(*roster, generator_context, 2, message, final_signature))
        return EXIT_FAILURE;
    const auto registration3 = hta::create_registration(secret(17), 3, registry);
    const auto larger_roster =
        hta::build_roster({registration1, registration2, registration3}, registry);
    if (!larger_roster ||
        hta::verify_signature(*roster, generator_context, 1, message, final_signature) ||
        hta::verify_signature(*larger_roster, generator_context, 2, message, final_signature))
        return EXIT_FAILURE;
    const auto encoded_signature = hta::encode_signature(final_signature, 2);
    const auto decoded_signature =
        encoded_signature ? hta::decode_signature(*encoded_signature, 2) : std::nullopt;
    if (!encoded_signature || !decoded_signature ||
        !hta::verify_signature(*roster, generator_context, 2, message, *decoded_signature))
        return EXIT_FAILURE;
    auto trailing_bytes = *encoded_signature;
    trailing_bytes.push_back(0);
    const auto encoded_proof = hta::encode_authorization_proof(*proof, 2);
    if (hta::decode_signature(trailing_bytes, 2) || hta::encode_authorization_proof(*proof, 1) ||
        !encoded_proof || !hta::decode_authorization_proof(*encoded_proof, 2))
        return EXIT_FAILURE;

    const hta::PublicBytes digest(roster->digest.begin(), roster->digest.end());
    const hta::RoundOneRequest request{1, sid, digest, 2, message, masked_key, {1, 2}};
    const auto encoded_request = hta::encode_round_one_request(request);
    const auto decoded_request =
        encoded_request ? hta::decode_round_one_request(*encoded_request, 2) : std::nullopt;
    if (!encoded_request)
        return EXIT_FAILURE;
    for (std::size_t length = 0; length < encoded_request->size(); ++length) {
        const hta::PublicBytes truncated(encoded_request->begin(),
                                         encoded_request->begin() + length);
        if (hta::decode_round_one_request(truncated, 2))
            return EXIT_FAILURE;
    }
    auto wrong_suite = *encoded_request;
    wrong_suite[10] ^= 1;
    auto bad_outer_length = *encoded_request;
    std::fill(bad_outer_length.begin() + 1, bad_outer_length.begin() + 5, 0xff);
    auto wrong_outer_tag = *encoded_request;
    wrong_outer_tag.front() = 2;
    if (hta::decode_round_one_request(wrong_suite, 2) ||
        hta::decode_round_one_request(bad_outer_length, 2) ||
        hta::decode_round_one_request(wrong_outer_tag, 2) ||
        hta::decode_round_one_request(*encoded_request, 1))
        return EXIT_FAILURE;
    auto bad_request = encoded_request.value_or(hta::PublicBytes{});
    bad_request.push_back(0);
    const hta::RoundOneResponse round_one_response{1, sid, *first};
    const auto encoded_round_one_response = hta::encode_round_one_response(round_one_response);
    const auto decoded_round_one_response =
        encoded_round_one_response ? hta::decode_round_one_response(*encoded_round_one_response)
                                   : std::nullopt;
    const hta::RoundTwoRequest round_two_request{1, sid, *aggregate};
    const auto encoded_round_two_request = hta::encode_round_two_request(round_two_request);
    const auto decoded_round_two_request =
        encoded_round_two_request ? hta::decode_round_two_request(*encoded_round_two_request)
                                  : std::nullopt;
    const hta::RoundTwoResponse round_two_response{1, sid, *response1};
    const auto encoded_round_two_response = hta::encode_round_two_response(round_two_response);
    const auto decoded_round_two_response =
        encoded_round_two_response ? hta::decode_round_two_response(*encoded_round_two_response)
                                   : std::nullopt;
    const auto encoded_registration = hta::encode_registration(registration1);
    const auto decoded_registration =
        encoded_registration ? hta::decode_registration(*encoded_registration) : std::nullopt;
    if (!decoded_request || decoded_request->subset != request.subset ||
        hta::decode_round_one_request(bad_request, 2) || !decoded_round_one_response ||
        !decoded_round_two_request || !decoded_round_two_response || !decoded_registration ||
        decoded_registration->index != registration1.index)
        return EXIT_FAILURE;
    const hta::RoundTwoResponse fixed_vector{1, {'s'}, hta::PublicBytes(32, 0)};
    hta::PublicBytes expected_vector{
        1,   0,   0,   0,   97,  2,   0,   0,   0,   16,  'H', 'T', 'A', '-', 's', 'e', 'c', 'p',
        '2', '5', '6', 'k', '1', '-', 'v', '1', 2,   0,   0,   0,   15,  'R', 'O', 'U', 'N', 'D',
        '2', '-', 'R', 'E', 'S', 'P', 'O', 'N', 'S', 'E', 3,   0,   0,   0,   8,   0,   0,   0,
        0,   0,   0,   0,   1,   2,   0,   0,   0,   1,   's', 5,   0,   0,   0,   32};
    expected_vector.insert(expected_vector.end(), 32, 0);
    if (hta::encode_round_two_response(fixed_vector) != expected_vector)
        return EXIT_FAILURE;
    auto noncanonical_response = *encoded_round_two_response;
    std::fill(noncanonical_response.end() - 32, noncanonical_response.end(), 0xff);
    if (hta::decode_round_two_response(noncanonical_response))
        return EXIT_FAILURE;
    const auto surplus_proof = hta::prove_authorization(
        *roster, generator_context, 1, message, signature->masked_key, {1, 1}, {1, 0}, secret(13));
    if (!surplus_proof || !hta::verify_authorization(*roster, generator_context, 1, message,
                                                     signature->masked_key, *surplus_proof))
        return EXIT_FAILURE;
    auto tampered_proof = *proof;
    tampered_proof.mu.back() ^= 1;
    auto bad_linkage = *proof;
    bad_linkage.Qs.back() ^= 1;
    auto bad_inner_product = *proof;
    bad_inner_product.t_hat.back() ^= 1;
    auto bad_left_coordinate = *proof;
    bad_left_coordinate.vL[0].back() ^= 1;
    auto bad_right_coordinate = *proof;
    bad_right_coordinate.vR[0].back() ^= 1;
    auto bad_tau_x = *proof;
    bad_tau_x.tau_x.back() ^= 1;
    const auto wrong_masked_key = roster->public_keys[1];
    if (hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  tampered_proof) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_linkage) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_inner_product) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_left_coordinate) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_right_coordinate) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_tau_x) ||
        hta::verify_authorization(*roster, generator_context, 2, message, wrong_masked_key,
                                  *proof) ||
        hta::verify_signature(*roster, generator_context, 2, {'x'}, final_signature) ||
        hta::prove_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                 {1, 0}, {0, 0}, secret(13)) ||
        hta::prove_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                 {2, 0}, {0, 0}, secret(13)) ||
        hta::prove_authorization(*roster, generator_context, 1, message, signature->masked_key,
                                 {1, 1}, {0, 0}, secret(13)))
        return EXIT_FAILURE;

    auto bad_A = *proof;
    bad_A.A.back() ^= 1;
    auto bad_S = *proof;
    bad_S.S.back() ^= 1;
    auto bad_T1 = *proof;
    bad_T1.T1.back() ^= 1;
    auto bad_T2 = *proof;
    bad_T2.T2.back() ^= 1;
    if (hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_A) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_S) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_T1) ||
        hta::verify_authorization(*roster, generator_context, 2, message, signature->masked_key,
                                  bad_T2))
        return EXIT_FAILURE;

    const hta::PublicBytes identity{0};
    auto identity_masked_key = final_signature;
    identity_masked_key.schnorr.masked_key = identity;
    auto identity_nonce = final_signature;
    identity_nonce.schnorr.nonce = identity;
    auto bad_schnorr_response = final_signature;
    bad_schnorr_response.schnorr.response.assign(32, 0);
    auto changed_nonce = final_signature;
    changed_nonce.schnorr.nonce = {0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                                   0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
                                   0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
                                   0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    if (hta::verify_signature(*roster, generator_context, 2, message, identity_masked_key) ||
        hta::verify_signature(*roster, generator_context, 2, message, identity_nonce) ||
        hta::verify_signature(*roster, generator_context, 2, message, bad_schnorr_response) ||
        hta::verify_signature(*roster, generator_context, 2, message, changed_nonce))
        return EXIT_FAILURE;

    std::vector<hta::AuthorizationProof> identity_proofs(5, *proof);
    identity_proofs[0].A = identity;
    identity_proofs[1].S = identity;
    identity_proofs[2].Qs = identity;
    identity_proofs[3].T1 = identity;
    identity_proofs[4].T2 = identity;
    for (const auto &identity_proof : identity_proofs) {
        const auto identity_wire = hta::encode_authorization_proof(identity_proof, 2);
        if (!identity_wire || !hta::decode_authorization_proof(*identity_wire, 2))
            return EXIT_FAILURE;
        (void)hta::verify_authorization(*roster, generator_context, 2, message,
                                        signature->masked_key, identity_proof);
    }

    auto missing_commitments =
        hta::CoordinatorSession::begin(*roster, {'m', 'i', 's', 's'}, 1, message, {1}, secret(17));
    if (!missing_commitments || missing_commitments->collect_commitments({}) ||
        missing_commitments->collect_commitments({}))
        return EXIT_FAILURE;

    const hta::PublicBytes long_sid(257, 's');
    if (hta::CoordinatorSession::begin(*roster, {}, 1, message, {1}, secret(23)) ||
        hta::CoordinatorSession::begin(*roster, long_sid, 1, message, {1}, secret(23)) ||
        hta::CoordinatorSession::begin(*roster, {'x'}, 0, message, {1}, secret(23)) ||
        hta::CoordinatorSession::begin(*roster, {'x'}, 1, message, {2, 1}, secret(23)) ||
        hta::CoordinatorSession::begin(*roster, {'x'}, 1, message, {1, 1}, secret(23)))
        return EXIT_FAILURE;

    hta::Signer rejected_inputs(1, secret(7));
    hta::PublicBytes maximum_sid(256, 's');
    if (rejected_inputs.round1(*roster, {}, 1, message, masked_key, {1}) ||
        rejected_inputs.round1(*roster, long_sid, 1, message, masked_key, {1}) ||
        rejected_inputs.round1(*roster, maximum_sid, 0, message, masked_key, {1}) ||
        rejected_inputs.round1(*roster, maximum_sid, 1, message, masked_key, {1, 1}) ||
        !rejected_inputs.round1(*roster, maximum_sid, 1, message, masked_key, {1}))
        return EXIT_FAILURE;

    auto invalid_shares =
        hta::CoordinatorSession::begin(*roster, {'b', 'a', 'd'}, 1, message, {1}, secret(19));
    if (!invalid_shares ||
        !invalid_shares->collect_commitments(
            {{1, {roster->public_keys[0], roster->public_keys[0]}}}) ||
        invalid_shares->aggregate_responses({{1, hta::PublicBytes(32, 0)}}) ||
        invalid_shares->aggregate_responses({{1, hta::PublicBytes(32, 0)}}))
        return EXIT_FAILURE;

    hta::Signer burn_on_abort(1, secret(7));
    const hta::PublicBytes invalid_sid{'b', 'a', 'd'};
    if (!burn_on_abort.round1(*roster, invalid_sid, 1, message, masked_key, {1}) ||
        burn_on_abort.round2(invalid_sid, {0}, aggregate->second) ||
        burn_on_abort.round2(invalid_sid, aggregate->first, aggregate->second))
        return EXIT_FAILURE;

    hta::Signer changed_context(1, secret(7));
    const hta::PublicBytes signing_sid{'s', 'i', 'd', '2'};
    if (!changed_context.round1(*roster, signing_sid, 1, message, masked_key, {1}) ||
        changed_context.round2({'s', 'i', 'd', '3'}, aggregate->first, aggregate->second) ||
        !changed_context.round2(signing_sid, aggregate->first, aggregate->second))
        return EXIT_FAILURE;

    hta::Signer no_round_one(1, secret(7));
    hta::Signer outside_subset(2, secret(11));
    hta::Signer below_threshold(1, secret(7));
    if (no_round_one.round2({'n', 'o'}, aggregate->first, aggregate->second) ||
        outside_subset.round1(*roster, {'o', 'u', 't'}, 1, message, masked_key, {1}) ||
        below_threshold.round1(*roster, {'u', 'n', 'd'}, 2, message, masked_key, {1}))
        return EXIT_FAILURE;

    const auto alternate1 = hta::create_registration(secret(19), 1, registry);
    const auto alternate2 = hta::create_registration(secret(23), 2, registry);
    const auto alternate_roster = hta::build_roster({alternate1, alternate2}, registry);
    if (!alternate_roster ||
        hta::verify_signature(*alternate_roster, generator_context, 2, message, final_signature))
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
    auto reserve_distinct = [&](const hta::PublicBytes &distinct_sid) {
        if (parallel_sessions.round1(*roster, distinct_sid, 1, message, masked_key, {1}))
            ++parallel_accepted;
    };
    std::thread distinct_first(reserve_distinct, hta::PublicBytes{'a'});
    std::thread distinct_second(reserve_distinct, hta::PublicBytes{'b'});
    distinct_first.join();
    distinct_second.join();
    if (parallel_accepted != 2)
        return EXIT_FAILURE;

    hta::Signer bounded(1, secret(7), 1);
    const hta::PublicBytes bounded_sid{'c', 'a', 'p'};
    const auto bounded_commitments =
        bounded.round1(*roster, bounded_sid, 1, message, masked_key, {1});
    if (!bounded_commitments ||
        bounded.round1(*roster, {'n', 'e', 'w'}, 1, message, masked_key, {1}) ||
        !bounded.round2(bounded_sid, bounded_commitments->first, bounded_commitments->second) ||
        bounded.round1(*roster, {'n', 'e', 'w'}, 1, message, masked_key, {1}))
        return EXIT_FAILURE;

    bool rejected_invalid_capacity = false;
    try {
        hta::Signer invalid_capacity(1, secret(7), hta::Signer::maximum_remembered_sessions + 1);
    } catch (const std::invalid_argument &) {
        rejected_invalid_capacity = true;
    }
    if (!rejected_invalid_capacity)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
