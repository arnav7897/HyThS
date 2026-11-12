#include "hta/authorization.hpp"
#include "hta/parameters.hpp"
#include "hta/protocol_encoding.hpp"

#include <array>
#include <iostream>
#include <map>
#include <memory>

namespace {
using namespace hta;

SecretScalar secret(unsigned value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes[30] = static_cast<std::uint8_t>(value >> 8);
    bytes[31] = static_cast<std::uint8_t>(value);
    return SecretScalar::from_canonical(bytes);
}

bool run_case(unsigned n, unsigned threshold, unsigned count) {
    const PublicBytes registry{'r'}, context{'g'}, sid{'s'}, message{'m'};
    std::vector<Registration> registrations;
    for (unsigned i = 1; i <= n; ++i)
        registrations.push_back(create_registration(secret(i), i, registry));
    auto roster = build_roster(registrations, registry);
    if (!roster)
        return false;

    std::vector<std::uint64_t> subset;
    for (unsigned i = 1; i <= count; ++i)
        subset.push_back(i);
    auto coordinator =
        CoordinatorSession::begin(*roster, sid, threshold, message, subset, secret(100));
    if (!coordinator)
        return false;
    std::vector<std::unique_ptr<Signer>> signers;
    std::map<std::uint64_t, RoundOneCommitments> commitments;
    for (unsigned i = 1; i <= count; ++i) {
        signers.push_back(std::make_unique<Signer>(i, secret(i)));
        auto commitment = signers.back()->round1(*roster, sid, threshold, message,
                                                 coordinator->masked_key(), subset);
        if (!commitment)
            return false;
        commitments.emplace(i, *commitment);
    }
    auto aggregate = coordinator->collect_commitments(commitments);
    if (!aggregate)
        return false;
    std::map<std::uint64_t, PublicBytes> responses;
    for (unsigned i = 1; i <= count; ++i) {
        auto response = signers[i - 1]->round2(sid, aggregate->first, aggregate->second);
        if (!response)
            return false;
        responses.emplace(i, *response);
    }
    auto schnorr = coordinator->aggregate_responses(responses);
    if (!schnorr)
        return false;
    auto dims = dimensions(n, threshold);
    if (!dims)
        return false;
    std::vector<std::uint8_t> selectors(n, 0), surplus(dims->ell, 0);
    for (unsigned i = 0; i < count; ++i)
        selectors[i] = 1;
    for (unsigned i = 0; i < dims->ell; ++i)
        surplus[i] = static_cast<std::uint8_t>(((count - threshold) >> i) & 1U);
    auto proof = prove_authorization(*roster, context, threshold, message, schnorr->masked_key,
                                     selectors, surplus, secret(100));
    if (!proof)
        return false;
    const FinalSignature valid{*schnorr, *proof};
    auto encoded = encode_signature(valid, n);
    auto decoded = encoded ? decode_signature(*encoded, n) : std::nullopt;
    if (!decoded)
        return false;

    // Individual spec-literal verification is the oracle for the batch verifier.
    auto compare = [&](const FinalSignature &candidate, const PublicBytes &candidate_message,
                       bool expected) {
        const bool individual =
            verify_signature(*roster, context, threshold, candidate_message, candidate);
        const bool single =
            batch_verify_signatures(*roster, context, threshold, {candidate_message}, {candidate});
        const bool mixed = batch_verify_signatures(
            *roster, context, threshold, {message, candidate_message}, {valid, candidate});
        return individual == expected && single == individual && mixed == individual;
    };
    if (!compare(*decoded, message, true) || !compare(valid, {'x'}, false))
        return false;
    for (const std::size_t size : std::array<std::size_t, 7>{{1, 2, 4, 8, 16, 32, 64}}) {
        const std::vector<FinalSignature> batch(size, valid);
        const std::vector<PublicBytes> batch_messages(size, message);
        if (!batch_verify_signatures(*roster, context, threshold, batch_messages, batch))
            return false;
        for (const auto index : {std::size_t{0}, size / 2, size - 1}) {
            auto invalid_batch = batch;
            invalid_batch[index].schnorr.response.back() ^= 1;
            if (batch_verify_signatures(*roster, context, threshold, batch_messages,
                                        invalid_batch))
                return false;
        }
    }
    if (batch_verify_signatures(*roster, context, threshold,
                                std::vector<PublicBytes>(65, message),
                                std::vector<FinalSignature>(65, valid)))
        return false;
    for (unsigned field = 0; field < 11; ++field) {
        auto altered = valid;
        PublicBytes *value = nullptr;
        switch (field) {
        case 0:
            value = &altered.schnorr.response;
            break;
        case 1:
            value = &altered.schnorr.nonce;
            break;
        case 2:
            value = &altered.schnorr.masked_key;
            break;
        case 3:
            value = &altered.authorization.A;
            break;
        case 4:
            value = &altered.authorization.S;
            break;
        case 5:
            value = &altered.authorization.Qs;
            break;
        case 6:
            value = &altered.authorization.T1;
            break;
        case 7:
            value = &altered.authorization.T2;
            break;
        case 8:
            value = &altered.authorization.t_hat;
            break;
        case 9:
            value = &altered.authorization.mu;
            break;
        default:
            value = &altered.authorization.tau_x;
            break;
        }
        value->back() ^= 1;
        if (!compare(altered, message, false))
            return false;
    }
    for (std::size_t coordinate : {std::size_t{0}, proof->vL.size() - 1}) {
        auto altered = valid;
        altered.authorization.vL[coordinate].back() ^= 1;
        if (!compare(altered, message, false))
            return false;
        altered = valid;
        altered.authorization.vR[coordinate].back() ^= 1;
        if (!compare(altered, message, false))
            return false;
    }
    auto wrong_size = valid;
    wrong_size.authorization.vL.pop_back();
    auto empty_point = valid;
    empty_point.authorization.A.clear();
    auto malformed_scalar = valid;
    malformed_scalar.authorization.vR[0].assign(32, 0xff);
    auto noncanonical = valid;
    noncanonical.schnorr.response.assign(32, 0xff);
    auto identity = valid;
    identity.schnorr.nonce = {0};
    const auto other_threshold = threshold == n ? threshold - 1 : threshold + 1;
    return compare(wrong_size, message, false) && compare(empty_point, message, false) &&
           compare(malformed_scalar, message, false) && compare(noncanonical, message, false) &&
           compare(identity, message, false) &&
           !verify_signature(*roster, context, other_threshold, message, valid) &&
           !batch_verify_signatures(*roster, context, other_threshold, {message}, {valid}) &&
           !verify_signature(*roster, {'x'}, threshold, message, valid) &&
           !batch_verify_signatures(*roster, {'x'}, threshold, {message}, {valid});
}
} // namespace

int main() {
    for (const auto &params : std::array<std::array<unsigned, 3>, 8>{{{1, 1, 1},
                                                                      {2, 1, 1},
                                                                      {2, 1, 2},
                                                                      {4, 2, 2},
                                                                      {4, 2, 4},
                                                                      {8, 4, 5},
                                                                      {8, 8, 8},
                                                                      {16, 7, 11}}}) {
        if (!run_case(params[0], params[1], params[2])) {
            std::cerr << "verification mismatch n=" << params[0] << " t=" << params[1]
                      << " k=" << params[2] << '\n';
            return 1;
        }
    }
    return 0;
}
