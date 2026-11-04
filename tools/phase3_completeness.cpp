#include "hta/authorization.hpp"
#include "hta/parameters.hpp"
#include "hta/secret_scalar.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
hta::SecretScalar scalar(std::uint32_t value) {
    std::array<std::uint8_t, 32> encoded{};
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        encoded[31 - i] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
    return hta::SecretScalar::from_canonical(encoded);
}

hta::PublicBytes session_id(std::uint64_t value) {
    hta::PublicBytes out{'p', 'h', 'a', 's', 'e', '3'};
    for (int i = 7; i >= 0; --i)
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    return out;
}

void run_parameter_set(std::uint32_t n, std::uint32_t threshold, std::uint64_t count) {
    const hta::PublicBytes registry{'p', 'h', 'a', 's', 'e', '3', '-', 'c', 'o', 'm', 'p'};
    const hta::PublicBytes generator_context{'p', 'h', 'a', 's', 'e', '3', '-', 'g', 'e', 'n'};
    const hta::PublicBytes message{'c', 'o', 'm', 'p', 'l', 'e', 't', 'e', 'n', 'e', 's', 's'};
    std::vector<hta::SecretScalar> keys;
    std::vector<hta::Registration> registrations;
    keys.reserve(n);
    registrations.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        keys.push_back(scalar(i + 2));
        registrations.push_back(hta::create_registration(keys.back(), i + 1, registry));
    }
    const auto roster = hta::build_roster(registrations, registry);
    if (!roster)
        throw std::runtime_error("roster setup failed");

    for (std::uint64_t run = 0; run < count; ++run) {
        const std::uint32_t selected_count = (run % 2 == 0) ? threshold : n;
        std::vector<std::uint64_t> subset;
        std::vector<std::uint8_t> selectors(n, 0);
        for (std::uint32_t i = 0; i < selected_count; ++i) {
            subset.push_back(i + 1);
            selectors[i] = 1;
        }
        const auto sid = session_id((static_cast<std::uint64_t>(n) << 56) |
                                    (static_cast<std::uint64_t>(threshold) << 48) | run);
        const auto tweak_value = static_cast<std::uint32_t>(1000 + (run % 100000));
        auto coordinator = hta::CoordinatorSession::begin(*roster, sid, threshold, message, subset,
                                                          scalar(tweak_value));
        if (!coordinator)
            throw std::runtime_error("coordinator setup failed at run " + std::to_string(run));

        std::map<std::uint64_t, std::unique_ptr<hta::Signer>> signers;
        std::map<std::uint64_t, hta::RoundOneCommitments> commitments;
        for (const auto index : subset) {
            auto signer =
                std::make_unique<hta::Signer>(index, scalar(static_cast<std::uint32_t>(index + 1)));
            const auto response =
                signer->round1(*roster, sid, threshold, message, coordinator->masked_key(), subset);
            if (!response)
                throw std::runtime_error("round one failed at run " + std::to_string(run));
            commitments.emplace(index, *response);
            signers.emplace(index, std::move(signer));
        }
        const auto aggregate = coordinator->collect_commitments(commitments);
        if (!aggregate)
            throw std::runtime_error("commitment aggregation failed at run " + std::to_string(run));
        std::map<std::uint64_t, hta::PublicBytes> responses;
        for (auto &[index, signer] : signers) {
            const auto response = signer->round2(sid, aggregate->first, aggregate->second);
            if (!response || !coordinator->verify_partial_response(index, *response))
                throw std::runtime_error("round two failed at run " + std::to_string(run));
            responses.emplace(index, *response);
        }
        const auto signature = coordinator->aggregate_responses(responses);
        if (!signature)
            throw std::runtime_error("signature aggregation failed at run " + std::to_string(run));

        const auto dims = hta::dimensions(n, threshold);
        std::vector<std::uint8_t> surplus_bits(dims->ell, 0);
        auto surplus = selected_count - threshold;
        for (std::size_t bit = 0; bit < surplus_bits.size(); ++bit) {
            surplus_bits[bit] = static_cast<std::uint8_t>(surplus & 1U);
            surplus >>= 1;
        }
        const auto proof = hta::prove_authorization(*roster, generator_context, threshold, message,
                                                    signature->masked_key, selectors, surplus_bits,
                                                    scalar(tweak_value));
        if (!proof)
            throw std::runtime_error("authorization proof failed at run " + std::to_string(run));
        const hta::FinalSignature final_signature{*signature, *proof};
        if (!hta::verify_signature(*roster, generator_context, threshold, message, final_signature))
            throw std::runtime_error("verification failed at run " + std::to_string(run));
    }
    std::cout << "n=" << n << " threshold=" << threshold << " runs=" << count
              << " subset_sizes=" << threshold << ',' << n << " PASS\n";
}
} // namespace

int main(int argc, char **argv) {
    try {
        std::cout.setf(std::ios::unitbuf);
        const std::uint64_t count = argc == 1 ? 10000 : std::stoull(argv[1]);
        if (argc > 2 || count < 10000)
            throw std::runtime_error("run count must be at least 10000");
        run_parameter_set(1, 1, count);
        run_parameter_set(2, 1, count);
        run_parameter_set(2, 2, count);
        run_parameter_set(3, 2, count);
        return EXIT_SUCCESS;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
