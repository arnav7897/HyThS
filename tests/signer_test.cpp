#include "hta/coordinator.hpp"
#include "hta/authorization.hpp"
#include "hta/protocol_encoding.hpp"
#include "hta/signer.hpp"

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
    if (!response1 || !response2 ||
        signer1.round2(sid, aggregate->first, aggregate->second))
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
    const auto encoded_signature = hta::encode_signature(final_signature, 2);
    const auto decoded_signature = encoded_signature
                                      ? hta::decode_signature(*encoded_signature, 2)
                                      : std::nullopt;
    if (!encoded_signature || !decoded_signature ||
        !hta::verify_signature(*roster, generator_context, 2, message, *decoded_signature))
        return EXIT_FAILURE;
    auto trailing_bytes = *encoded_signature;
    trailing_bytes.push_back(0);
    const auto encoded_proof = hta::encode_authorization_proof(*proof, 2);
    if (hta::decode_signature(trailing_bytes, 2) ||
        hta::encode_authorization_proof(*proof, 1) ||
        !encoded_proof || !hta::decode_authorization_proof(*encoded_proof, 2))
        return EXIT_FAILURE;

    const hta::PublicBytes digest(roster->digest.begin(), roster->digest.end());
    const hta::RoundOneRequest request{1, sid, digest, 2, message, masked_key, {1, 2}};
    const auto encoded_request = hta::encode_round_one_request(request);
    const auto decoded_request = encoded_request
                                     ? hta::decode_round_one_request(*encoded_request, 2)
                                     : std::nullopt;
    auto bad_request = encoded_request.value_or(hta::PublicBytes{});
    bad_request.push_back(0);
    const hta::RoundOneResponse round_one_response{1, sid, *first};
    const auto encoded_round_one_response = hta::encode_round_one_response(round_one_response);
    const auto decoded_round_one_response = encoded_round_one_response
                                                ? hta::decode_round_one_response(
                                                      *encoded_round_one_response)
                                                : std::nullopt;
    const hta::RoundTwoRequest round_two_request{1, sid, *aggregate};
    const auto encoded_round_two_request = hta::encode_round_two_request(round_two_request);
    const auto decoded_round_two_request = encoded_round_two_request
                                              ? hta::decode_round_two_request(
                                                    *encoded_round_two_request)
                                              : std::nullopt;
    const hta::RoundTwoResponse round_two_response{1, sid, *response1};
    const auto encoded_round_two_response = hta::encode_round_two_response(round_two_response);
    const auto decoded_round_two_response = encoded_round_two_response
                                                ? hta::decode_round_two_response(
                                                      *encoded_round_two_response)
                                                : std::nullopt;
    const auto encoded_registration = hta::encode_registration(registration1);
    const auto decoded_registration = encoded_registration
                                          ? hta::decode_registration(*encoded_registration)
                                          : std::nullopt;
    if (!decoded_request || decoded_request->subset != request.subset ||
        hta::decode_round_one_request(bad_request, 2) ||
        !decoded_round_one_response || !decoded_round_two_request || !decoded_round_two_response ||
        !decoded_registration || decoded_registration->index != registration1.index)
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
    if (hta::verify_authorization(*roster, generator_context, 2, message,
                                  signature->masked_key, tampered_proof) ||
        hta::verify_authorization(*roster, generator_context, 2, message,
                                  signature->masked_key, bad_linkage) ||
        hta::verify_authorization(*roster, generator_context, 2, message,
                                  signature->masked_key, bad_inner_product) ||
        hta::verify_signature(*roster, generator_context, 2, {'x'}, final_signature) ||
        hta::prove_authorization(*roster, generator_context, 2, message,
                                 signature->masked_key, {1, 0}, {0, 0}, secret(13)))
        return EXIT_FAILURE;

    auto missing_commitments =
        hta::CoordinatorSession::begin(*roster, {'m', 'i', 's', 's'}, 1, message, {1}, secret(17));
    if (!missing_commitments || missing_commitments->collect_commitments({}) ||
        missing_commitments->collect_commitments({}))
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
