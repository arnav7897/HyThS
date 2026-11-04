#include "hta/coordinator.hpp"
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
