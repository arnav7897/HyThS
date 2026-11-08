#include "hta/authorization.hpp"
#include "hta/secret_group.hpp"

#include <array>
#include <atomic>
#include <cstdlib>
#include <map>
#include <memory>
#include <thread>

namespace {
using namespace hta;

SecretScalar secret(unsigned value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes[30] = static_cast<std::uint8_t>(value >> 8);
    bytes[31] = static_cast<std::uint8_t>(value);
    return SecretScalar::from_canonical(bytes);
}

std::optional<Roster> roster_for(unsigned n) {
    std::vector<Registration> registrations;
    for (unsigned i = 1; i <= n; ++i)
        registrations.push_back(create_registration(secret(i), i, {'r'}));
    return build_roster(registrations, {'r'});
}

bool dropout_restart() {
    auto roster = roster_for(8);
    if (!roster)
        return false;
    const PublicBytes old_sid{'o'}, new_sid{'n'}, message{'m'}, context{'g'};
    const std::vector<std::uint64_t> five{1, 2, 3, 4, 5}, four{1, 2, 3, 4};
    std::vector<std::unique_ptr<Signer>> signers;
    for (unsigned i = 1; i <= 5; ++i)
        signers.push_back(std::make_unique<Signer>(i, secret(i)));
    auto old = CoordinatorSession::begin(*roster, old_sid, 4, message, five, secret(20));
    if (!old)
        return false;
    std::map<std::uint64_t, RoundOneCommitments> old_commitments;
    for (unsigned i = 0; i < 4; ++i) {
        auto c = signers[i]->round1(*roster, old_sid, 4, message, old->masked_key(), five);
        if (!c)
            return false;
        old_commitments.emplace(i + 1, *c);
    }
    if (old->collect_commitments(old_commitments))
        return false;
    for (unsigned i = 0; i < 4; ++i) {
        if (!signers[i]->cancel(old_sid) || signers[i]->cancel(old_sid) ||
            signers[i]->round1(*roster, old_sid, 4, message, old->masked_key(), five) ||
            signers[i]->round2(old_sid, old_commitments[1].first, old_commitments[1].second))
            return false;
    }
    if (CoordinatorSession::begin(*roster, new_sid, 4, message, {1, 2, 3}, secret(21)))
        return false;
    auto current = CoordinatorSession::begin(*roster, new_sid, 4, message, four, secret(21));
    if (!current)
        return false;
    std::map<std::uint64_t, RoundOneCommitments> commitments;
    for (unsigned i = 0; i < 4; ++i) {
        auto c = signers[i]->round1(*roster, new_sid, 4, message, current->masked_key(), four);
        if (!c)
            return false;
        commitments.emplace(i + 1, *c);
    }
    auto aggregate = current->collect_commitments(commitments);
    if (!aggregate)
        return false;
    std::map<std::uint64_t, PublicBytes> responses;
    for (unsigned i = 0; i < 4; ++i) {
        auto response = signers[i]->round2(new_sid, aggregate->first, aggregate->second);
        if (!response)
            return false;
        responses.emplace(i + 1, *response);
    }
    auto signature = current->aggregate_responses(responses);
    if (!signature)
        return false;
    auto proof = prove_authorization(*roster, context, 4, message, signature->masked_key,
                                     {1, 1, 1, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, secret(21));
    return proof && verify_signature(*roster, context, 4, message, {*signature, *proof});
}

bool cancellation_race() {
    auto roster = roster_for(1);
    if (!roster)
        return false;
    Signer signer(1, secret(1));
    const PublicBytes sid{'r'};
    auto c = signer.round1(*roster, sid, 1, {'m'}, roster->public_keys[0], {1});
    if (!c)
        return false;
    std::atomic<unsigned> winners{0};
    std::thread cancel([&] {
        if (signer.cancel(sid))
            ++winners;
    });
    std::thread response([&] {
        if (signer.round2(sid, c->first, c->second))
            ++winners;
    });
    cancel.join();
    response.join();
    return winners == 1 && !signer.cancel(sid) &&
           !signer.round1(*roster, sid, 1, {'m'}, roster->public_keys[0], {1});
}

bool automatic_timeout() {
    auto roster = roster_for(1);
    if (!roster)
        return false;
    Signer signer(1, secret(1), 10, std::chrono::milliseconds(30));
    const PublicBytes sid{'t'};
    auto c = signer.round1(*roster, sid, 1, {'m'}, roster->public_keys[0], {1});
    if (!c)
        return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    return !signer.cancel(sid) && !signer.round2(sid, c->first, c->second) &&
           !signer.round1(*roster, sid, 1, {'m'}, roster->public_keys[0], {1}) &&
           signer.round1(*roster, {'u'}, 1, {'m'}, roster->public_keys[0], {1}).has_value();
}

bool large_surplus() {
    auto roster = roster_for(257);
    if (!roster)
        return false;
    auto coordinator = CoordinatorSession::begin(
        *roster, {'l'}, 1, {'m'},
        [&] {
            std::vector<std::uint64_t> indices;
            for (unsigned i = 1; i <= 257; ++i)
                indices.push_back(i);
            return indices;
        }(),
        secret(300));
    if (!coordinator)
        return false;
    std::vector<std::uint8_t> selectors(257, 1), surplus(9, 0);
    surplus[8] = 1;
    auto proof = prove_authorization(*roster, {'g'}, 1, {'m'}, coordinator->masked_key(), selectors,
                                     surplus, secret(300));
    if (!proof ||
        !verify_authorization(*roster, {'g'}, 1, {'m'}, coordinator->masked_key(), *proof))
        return false;

    auto single = CoordinatorSession::begin(*roster, {'s'}, 1, {'m'}, {1}, secret(301));
    if (!single)
        return false;
    Signer signer(1, secret(1));
    auto commitment = signer.round1(*roster, {'s'}, 1, {'m'}, single->masked_key(), {1});
    if (!commitment)
        return false;
    auto aggregate = single->collect_commitments({{1, *commitment}});
    if (!aggregate)
        return false;
    auto response = signer.round2({'s'}, aggregate->first, aggregate->second);
    if (!response)
        return false;
    auto signature = single->aggregate_responses({{1, *response}});
    if (!signature)
        return false;
    selectors.assign(257, 0);
    selectors[0] = 1;
    surplus.assign(9, 0);
    auto single_proof = prove_authorization(*roster, {'g'}, 1, {'m'}, signature->masked_key,
                                            selectors, surplus, secret(301));
    if (!single_proof)
        return false;
    const FinalSignature final{*signature, *single_proof};
    const std::vector<PublicBytes> messages(41, PublicBytes{'m'});
    const std::vector<FinalSignature> signatures(41, final);
    auto invalid = std::vector<FinalSignature>(40, final);
    invalid.back().schnorr.response.back() ^= 1;
    const std::vector<PublicBytes> at_limit_messages(40, PublicBytes{'m'});
    return batch_verify_signatures(*roster, {'g'}, 1, at_limit_messages,
                                   std::vector<FinalSignature>(40, final)) &&
           !batch_verify_signatures(*roster, {'g'}, 1, at_limit_messages, invalid) &&
           !batch_verify_signatures(*roster, {'g'}, 1, messages, signatures);
}
} // namespace

int main() {
    return dropout_restart() && cancellation_race() && automatic_timeout() && large_surplus()
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
