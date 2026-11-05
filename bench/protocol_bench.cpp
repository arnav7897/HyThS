#include "hta/authorization.hpp"
#include "hta/protocol_encoding.hpp"
#include "hta/parameters.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using Bytes = hta::PublicBytes;
constexpr std::size_t sample_count = 5;

hta::SecretScalar scalar(std::uint64_t value) {
    std::array<std::uint8_t, 32> encoded{};
    for (std::size_t i = 0; i < 8; ++i) {
        encoded[31 - i] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
    return hta::SecretScalar::from_canonical(encoded);
}

std::uint64_t elapsed_ns(Clock::time_point start) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count());
}

template <typename T> T require(std::optional<T> value, const char *operation) {
    if (!value)
        throw std::runtime_error(std::string(operation) + " failed during benchmark");
    return std::move(*value);
}

struct Timing {
    std::uint64_t round1 = 0;
    std::uint64_t aggregate_commitments = 0;
    std::uint64_t round2 = 0;
    std::uint64_t verify_shares = 0;
    std::uint64_t aggregate_responses = 0;
    std::uint64_t prove = 0;
    std::uint64_t verify = 0;
    std::uint64_t serialize = 0;
    std::size_t signature_bytes = 0;
    hta::FinalSignature signature;
};

Timing run_once(const hta::Roster &roster, const std::vector<std::uint64_t> &subset,
                std::uint32_t threshold, const Bytes &message, const Bytes &generator_context,
                std::uint64_t sid_counter) {
    Bytes sid(8, 0);
    for (std::size_t i = 0; i < 8; ++i) {
        sid[7 - i] = static_cast<std::uint8_t>(sid_counter);
        sid_counter >>= 8;
    }
    auto tweak = hta::random_secret_scalar();
    auto proof_tweak = hta::SecretScalar::from_canonical(tweak.bytes());
    auto coordinator = require(
        hta::CoordinatorSession::begin(roster, sid, threshold, message, subset, std::move(tweak)),
        "coordinator begin");
    std::vector<std::unique_ptr<hta::Signer>> signers;
    signers.reserve(subset.size());
    for (const auto index : subset)
        signers.push_back(std::make_unique<hta::Signer>(index, scalar(index + 10)));

    Timing timing;
    std::map<std::uint64_t, hta::RoundOneCommitments> commitments;
    auto start = Clock::now();
    for (std::size_t i = 0; i < subset.size(); ++i) {
        const auto reply =
            signers[i]->round1(roster, sid, threshold, message, coordinator.masked_key(), subset);
        commitments.emplace(subset[i], require(reply, "signer round one"));
    }
    timing.round1 = elapsed_ns(start);

    start = Clock::now();
    const auto aggregate =
        require(coordinator.collect_commitments(commitments), "aggregate commitments");
    timing.aggregate_commitments = elapsed_ns(start);

    std::map<std::uint64_t, Bytes> responses;
    start = Clock::now();
    for (std::size_t i = 0; i < subset.size(); ++i)
        responses.emplace(subset[i],
                          require(signers[i]->round2(sid, aggregate.first, aggregate.second),
                                  "signer round two"));
    timing.round2 = elapsed_ns(start);

    start = Clock::now();
    for (const auto &[index, response] : responses)
        if (!coordinator.verify_partial_response(index, response))
            throw std::runtime_error("benchmark partial response failed verification");
    timing.verify_shares = elapsed_ns(start);

    start = Clock::now();
    const auto schnorr = require(coordinator.aggregate_responses(responses), "aggregate responses");
    timing.aggregate_responses = elapsed_ns(start);

    std::vector<std::uint8_t> selectors(roster.public_keys.size(), 0);
    for (const auto index : subset)
        selectors[index - 1] = 1;
    const auto dims =
        hta::dimensions(static_cast<std::uint32_t>(roster.public_keys.size()), threshold);
    if (!dims)
        throw std::runtime_error("invalid benchmark dimensions");
    std::vector<std::uint8_t> surplus_bits(dims->ell, 0);
    const auto surplus = subset.size() - threshold;
    for (std::size_t j = 0; j < surplus_bits.size(); ++j)
        surplus_bits[j] = static_cast<std::uint8_t>((surplus >> j) & 1U);
    start = Clock::now();
    const auto proof = require(hta::prove_authorization(roster, generator_context, threshold,
                                                        message, schnorr.masked_key, selectors,
                                                        surplus_bits, std::move(proof_tweak)),
                               "authorization prove");
    timing.prove = elapsed_ns(start);
    const hta::FinalSignature signature{schnorr, proof};
    timing.signature = signature;

    start = Clock::now();
    if (!hta::verify_signature(roster, generator_context, threshold, message, signature))
        throw std::runtime_error("benchmark signature failed verification");
    timing.verify = elapsed_ns(start);

    start = Clock::now();
    timing.signature_bytes =
        require(hta::encode_signature(signature, roster.public_keys.size()), "signature encode")
            .size();
    timing.serialize = elapsed_ns(start);
    return timing;
}

void print_stage(std::uint32_t n, std::uint32_t threshold, std::size_t signers, const char *name,
                 const std::array<std::uint64_t, sample_count> &samples, std::size_t iterations) {
    auto sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    std::cout << "{\"n\":" << n << ",\"threshold\":" << threshold << ",\"signers\":" << signers
              << ",\"stage\":\"" << name << "\",\"iterations_per_sample\":" << iterations
              << ",\"samples_ns\":[";
    for (std::size_t i = 0; i < samples.size(); ++i)
        std::cout << (i ? "," : "") << samples[i];
    std::cout << "],\"median_ns_per_op\":" << sorted[sample_count / 2] / iterations << "}\n";
}

void run_size(std::uint32_t n, std::uint32_t threshold, std::uint32_t signer_count,
              std::size_t iterations, std::uint64_t &sid_counter) {
    const Bytes registry{'p', 'h', 'a', 's', 'e', '3', '-', 'b', 'e', 'n', 'c', 'h'};
    const Bytes generator_context{'p', 'r', 'o', 't', 'o', 'c', 'o',
                                  'l', '-', 'b', 'e', 'n', 'c', 'h'};
    const Bytes message(32, 0x42);
    std::array<std::uint64_t, sample_count> setup_samples{};
    hta::Roster roster;
    for (std::size_t sample = 0; sample < sample_count; ++sample) {
        const auto setup_start = Clock::now();
        std::vector<hta::Registration> registrations;
        registrations.reserve(n);
        for (std::uint32_t i = 0; i < n; ++i)
            registrations.push_back(hta::create_registration(scalar(i + 11), i + 1, registry));
        roster = require(hta::build_roster(registrations, registry), "roster build");
        setup_samples[sample] = elapsed_ns(setup_start);
    }
    std::vector<std::uint64_t> subset;
    for (std::uint32_t i = 1; i <= signer_count; ++i)
        subset.push_back(i);

    (void)run_once(roster, subset, threshold, message, generator_context, sid_counter++);
    std::array<std::array<std::uint64_t, 8>, sample_count> samples{};
    std::array<std::uint64_t, sample_count> batch_reference_samples{}, batch_samples{};
    std::size_t output_size = 0;
    const auto batch_size = std::min<std::size_t>(iterations, 4);
    for (std::size_t sample = 0; sample < sample_count; ++sample) {
        std::vector<Bytes> batch_messages;
        std::vector<hta::FinalSignature> batch_signatures;
        batch_messages.reserve(batch_size);
        batch_signatures.reserve(batch_size);
        for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
            auto message_variant = message;
            const auto message_id = static_cast<std::uint64_t>(sample * iterations + iteration);
            for (std::size_t byte = 0; byte < 8; ++byte)
                message_variant.push_back(static_cast<std::uint8_t>(message_id >> (56 - byte * 8)));
            const auto result = run_once(roster, subset, threshold, message_variant,
                                         generator_context, sid_counter++);
            samples[sample][0] += result.round1;
            samples[sample][1] += result.aggregate_commitments;
            samples[sample][2] += result.round2;
            samples[sample][3] += result.verify_shares;
            samples[sample][4] += result.aggregate_responses;
            samples[sample][5] += result.prove;
            samples[sample][6] += result.verify;
            samples[sample][7] += result.serialize;
            output_size = result.signature_bytes;
            if (batch_signatures.size() < batch_size) {
                batch_messages.push_back(std::move(message_variant));
                batch_signatures.push_back(result.signature);
            }
        }
        auto start = Clock::now();
        for (std::size_t i = 0; i < batch_size; ++i)
            if (!hta::verify_signature(roster, generator_context, threshold, batch_messages[i],
                                       batch_signatures[i]))
                throw std::runtime_error("batch reference signature failed verification");
        batch_reference_samples[sample] = elapsed_ns(start);
        start = Clock::now();
        if (!hta::batch_verify_signatures(roster, generator_context, threshold, batch_messages,
                                          batch_signatures))
            throw std::runtime_error("batch signature verification failed");
        batch_samples[sample] = elapsed_ns(start);
    }
    print_stage(n, threshold, signer_count, "registration_and_roster", setup_samples, 1);
    constexpr std::array<const char *, 8> names{
        "signer_round1",       "aggregate_commitments", "signer_round2", "partial_verify_shares",
        "aggregate_responses", "authorization_prove",   "full_verify",   "serialize"};
    for (std::size_t stage = 0; stage < names.size(); ++stage) {
        std::array<std::uint64_t, sample_count> times{};
        for (std::size_t sample = 0; sample < sample_count; ++sample)
            times[sample] = samples[sample][stage];
        print_stage(n, threshold, signer_count, names[stage], times, iterations);
    }
    print_stage(n, threshold, signer_count, "batch_verify_reference", batch_reference_samples,
                batch_size);
    print_stage(n, threshold, signer_count, "batch_verify", batch_samples, batch_size);
    std::cout << "{\"n\":" << n << ",\"threshold\":" << threshold << ",\"signers\":" << signer_count
              << ",\"stage\":\"serialized_signature_size\",\"output_bytes\":" << output_size
              << "}\n";
}

std::uint32_t parse_u32(const char *text, const char *name) {
    std::size_t parsed = 0;
    const auto value = std::stoull(text, &parsed);
    if (parsed != std::string(text).size() || value > std::numeric_limits<std::uint32_t>::max())
        throw std::invalid_argument(std::string("invalid ") + name);
    return static_cast<std::uint32_t>(value);
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc != 1 && argc != 2 && argc != 4 && argc != 5)
            throw std::invalid_argument(
                "usage: protocol_bench [iterations [n threshold [signers]]]");
        const std::size_t iterations = argc > 1 ? std::stoul(argv[1]) : 1;
        if (iterations == 0 || iterations > 100)
            throw std::invalid_argument("iterations must be between 1 and 100");
        auto one = scalar(1);
        if (!hta::public_generator_multiply(Bytes(one.bytes().begin(), one.bytes().end())))
            throw std::runtime_error("backend warmup failed");
        auto secret_warmup = hta::random_secret_scalar();
        (void)hta::secret_generator_multiply(secret_warmup);
        std::uint64_t sid_counter = 1;
        if (argc == 4 || argc == 5) {
            const auto n = parse_u32(argv[2], "n");
            const auto threshold = parse_u32(argv[3], "threshold");
            const auto signer_count = argc == 5 ? parse_u32(argv[4], "signers") : threshold;
            if (n == 0 || n > 65535 || threshold == 0 || threshold > n ||
                signer_count < threshold || signer_count > n)
                throw std::invalid_argument("require 1 <= threshold <= signers <= n <= 65535");
            run_size(n, threshold, signer_count, iterations, sid_counter);
        } else {
            for (const auto n : {2U, 4U, 8U})
                run_size(n, (n + 1) / 2, (n + 1) / 2, iterations, sid_counter);
        }
        return EXIT_SUCCESS;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
