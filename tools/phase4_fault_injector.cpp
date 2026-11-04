#include "hta/coordinator.hpp"
#include "hta/protocol_encoding.hpp"
#include "hta/registration.hpp"
#include "hta/signer.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

hta::SecretScalar secret(std::uint8_t value) {
    std::array<std::uint8_t, 32> encoded{};
    encoded.back() = value;
    return hta::SecretScalar::from_canonical(encoded);
}

bool rejected_dropout(const hta::Roster &roster, std::uint64_t iteration) {
    const hta::PublicBytes sid{'f', 'i', static_cast<std::uint8_t>(iteration >> 8),
                               static_cast<std::uint8_t>(iteration)};
    auto coordinator = hta::CoordinatorSession::begin(roster, sid, 2, {'m'}, {1, 2}, secret(13));
    if (!coordinator)
        return false;
    hta::Signer signer(1, secret(7));
    const auto commitment = signer.round1(roster, sid, 2, {'m'}, coordinator->masked_key(), {1, 2});
    return commitment && !coordinator->collect_commitments({{1, *commitment}});
}

bool rejected_invalid_share(const hta::Roster &roster, std::uint64_t iteration) {
    const hta::PublicBytes sid{'i', 's', static_cast<std::uint8_t>(iteration >> 8),
                               static_cast<std::uint8_t>(iteration)};
    auto coordinator = hta::CoordinatorSession::begin(roster, sid, 2, {'m'}, {1, 2}, secret(13));
    if (!coordinator)
        return false;
    hta::Signer first_signer(1, secret(7));
    hta::Signer second_signer(2, secret(11));
    const auto first =
        first_signer.round1(roster, sid, 2, {'m'}, coordinator->masked_key(), {1, 2});
    const auto second =
        second_signer.round1(roster, sid, 2, {'m'}, coordinator->masked_key(), {1, 2});
    if (!first || !second)
        return false;
    const auto aggregate = coordinator->collect_commitments({{1, *first}, {2, *second}});
    if (!aggregate)
        return false;
    const auto first_response = first_signer.round2(sid, aggregate->first, aggregate->second);
    const auto second_response = second_signer.round2(sid, aggregate->first, aggregate->second);
    if (!first_response || !second_response)
        return false;
    auto corrupted = *first_response;
    corrupted.back() ^= 1;
    return !coordinator->verify_partial_response(1, corrupted) &&
           !coordinator->aggregate_responses({{1, corrupted}, {2, *second_response}});
}

bool rejected_malformed_message() {
    const hta::PublicBytes malformed{1, 0xff, 0xff, 0xff, 0xff};
    return !hta::decode_round_one_request(malformed, 2) &&
           !hta::decode_round_one_response(malformed) &&
           !hta::decode_round_two_request(malformed) && !hta::decode_round_two_response(malformed);
}

template <class Fault> bool report(const char *scenario, std::uint64_t iterations, Fault fault) {
    std::vector<std::int64_t> durations;
    durations.reserve(static_cast<std::size_t>(iterations));
    for (std::uint64_t i = 0; i < iterations; ++i) {
        const auto start = std::chrono::steady_clock::now();
        const bool rejected = fault(i);
        const auto stop = std::chrono::steady_clock::now();
        if (!rejected)
            return false;
        durations.push_back(
            std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count());
    }
    std::sort(durations.begin(), durations.end());
    std::cout << "{\"scenario\":\"" << scenario << "\",\"iterations\":" << iterations
              << ",\"rejected\":" << iterations
              << ",\"median_ns\":" << durations[durations.size() / 2]
              << ",\"max_ns\":" << durations.back() << "}\n";
    return true;
}

} // namespace

int main(int argc, char **argv) {
    std::uint64_t iterations = 1;
    if (argc > 2)
        return EXIT_FAILURE;
    if (argc == 2) {
        try {
            iterations = std::stoull(argv[1]);
        } catch (...) {
            return EXIT_FAILURE;
        }
    }
    if (iterations == 0 || iterations > 100000)
        return EXIT_FAILURE;

    const hta::PublicBytes registry{'p', 'h', 'a', 's', 'e', '4'};
    const auto first = hta::create_registration(secret(7), 1, registry);
    const auto second = hta::create_registration(secret(11), 2, registry);
    const auto roster = hta::build_roster({first, second}, registry);
    if (!roster ||
        !report("signer_dropout", iterations,
                [&](auto i) { return rejected_dropout(*roster, i); }) ||
        !report("invalid_partial_share", iterations,
                [&](auto i) { return rejected_invalid_share(*roster, i); }) ||
        !report("malformed_wire_message", iterations,
                [](auto) { return rejected_malformed_message(); }))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
