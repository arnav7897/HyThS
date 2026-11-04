#include "hta/authorization.hpp"
#include "hta/framing.hpp"
#include "hta/protocol_encoding.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secret_scalar.hpp"
#include "secret_scalar_test.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using hta::PublicBytes;

PublicBytes parse_hex(const std::string &value) {
    if (value.size() % 2 != 0)
        throw std::runtime_error("hex value has odd length");
    PublicBytes out;
    out.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const auto byte = std::stoul(value.substr(i, 2), nullptr, 16);
        if (byte > 255)
            throw std::runtime_error("hex byte out of range");
        out.push_back(static_cast<std::uint8_t>(byte));
    }
    return out;
}

std::string hex(const PublicBytes &bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 15]);
    }
    return out;
}

std::map<std::string, std::string> read_request(const char *path) {
    std::ifstream input(path);
    if (!input)
        throw std::runtime_error("cannot open KAT request");
    std::map<std::string, std::string> result;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line.front() == '#')
            continue;
        const auto separator = line.find('=');
        if (separator == std::string::npos || separator == 0 ||
            !result.emplace(line.substr(0, separator), line.substr(separator + 1)).second)
            throw std::runtime_error("malformed or duplicate KAT request field");
    }
    return result;
}

const std::string &field(const std::map<std::string, std::string> &request,
                         const std::string &name) {
    const auto found = request.find(name);
    if (found == request.end())
        throw std::runtime_error("missing KAT field: " + name);
    return found->second;
}

hta::SecretScalar secret(const std::string &encoded) {
    const auto bytes = parse_hex(encoded);
    if (bytes.size() != 32)
        throw std::runtime_error("secret scalar must be 32 bytes");
    std::array<std::uint8_t, 32> array{};
    std::copy(bytes.begin(), bytes.end(), array.begin());
    return hta::SecretScalar::from_canonical(array);
}

PublicBytes must(std::optional<PublicBytes> value) {
    if (!value)
        throw std::runtime_error("protocol operation failed while generating KAT");
    return std::move(*value);
}

PublicBytes context(const PublicBytes &sid, const hta::Roster &roster,
                    std::uint32_t threshold, const PublicBytes &message,
                    const PublicBytes &masked_key, const std::vector<std::uint64_t> &subset) {
    PublicBytes subset_bytes;
    for (const auto index : subset) {
        const auto encoded = hta::frame_integer(index);
        subset_bytes.insert(subset_bytes.end(), encoded.begin(), encoded.end());
    }
    const auto subset_transcript = hta::transcript("SUBSET", {hta::frame(6, subset_bytes)});
    const PublicBytes digest(roster.digest.begin(), roster.digest.end());
    return hta::transcript("CTX", {hta::frame(2, sid), hta::frame(2, digest),
                                   hta::frame_integer(threshold), hta::frame(2, message),
                                   hta::frame(4, masked_key), hta::frame(2, subset_transcript)});
}

std::string generate(const char *request_path) {
    const auto request = read_request(request_path);
    if (field(request, "format") != "hta-phase3-kat-v1")
        throw std::runtime_error("unsupported KAT request format");
    const auto seed = parse_hex(field(request, "seed"));
    if (seed.size() != 32)
        throw std::runtime_error("seed must be 32 bytes");

    std::uint64_t counter = 0;
    hta::testing::ScopedRandomBytes deterministic_rng([&](std::uint8_t *output, int length) {
        if (length < 0)
            return 0;
        int written = 0;
        while (written < length) {
            const auto encoded_counter = hta::frame_integer(counter++);
            const auto input = hta::transcript("KAT-RNG", {hta::frame(2, seed), encoded_counter});
            std::array<std::uint8_t, 32> block{};
            std::size_t block_size = 0;
            if (EVP_Q_digest(nullptr, "SHA256", nullptr, input.data(), input.size(), block.data(),
                             &block_size) != 1 ||
                block_size != block.size())
                return 0;
            const auto take = std::min<int>(length - written, static_cast<int>(block.size()));
            std::copy_n(block.begin(), take, output + written);
            written += take;
        }
        return 1;
    });

    const auto registry = parse_hex(field(request, "registry"));
    const auto generator_context = parse_hex(field(request, "generator_context"));
    const auto sid = parse_hex(field(request, "sid"));
    const auto message = parse_hex(field(request, "message"));
    const auto key1 = secret(field(request, "secret_key_1"));
    const auto key2 = secret(field(request, "secret_key_2"));
    const auto threshold = static_cast<std::uint32_t>(std::stoul(field(request, "threshold")));
    const std::vector<std::uint64_t> subset{1, 2};

    const auto registration1 = hta::create_registration(key1, 1, registry);
    const auto registration2 = hta::create_registration(key2, 2, registry);
    const auto roster = hta::build_roster({registration1, registration2}, registry);
    if (!roster)
        throw std::runtime_error("roster build failed");
    auto coordinator = hta::CoordinatorSession::begin(*roster, sid, threshold, message, subset,
                                                      secret(field(request, "tweak")));
    if (!coordinator)
        throw std::runtime_error("coordinator setup failed");
    hta::Signer signer1(1, secret(field(request, "secret_key_1")));
    hta::Signer signer2(2, secret(field(request, "secret_key_2")));
    const auto masked_key = coordinator->masked_key();
    const auto first = signer1.round1(*roster, sid, threshold, message, masked_key, subset);
    const auto second = signer2.round1(*roster, sid, threshold, message, masked_key, subset);
    if (!first || !second)
        throw std::runtime_error("signer round one failed");
    const auto aggregate = coordinator->collect_commitments({{1, *first}, {2, *second}});
    if (!aggregate)
        throw std::runtime_error("commitment aggregation failed");
    const auto response1 = signer1.round2(sid, aggregate->first, aggregate->second);
    const auto response2 = signer2.round2(sid, aggregate->first, aggregate->second);
    if (!response1 || !response2)
        throw std::runtime_error("signer round two failed");
    const auto signature = coordinator->aggregate_responses({{1, *response1}, {2, *response2}});
    if (!signature)
        throw std::runtime_error("response aggregation failed");
    const auto proof = hta::prove_authorization(*roster, generator_context, threshold, message,
                                                signature->masked_key, {1, 1}, {0, 0},
                                                secret(field(request, "tweak")));
    if (!proof)
        throw std::runtime_error("authorization proof failed");
    const hta::FinalSignature final_signature{*signature, *proof};
    if (!hta::verify_signature(*roster, generator_context, threshold, message, final_signature))
        throw std::runtime_error("generated signature did not verify");

    const auto proof_wire = hta::encode_authorization_proof(*proof, 2);
    const auto signature_wire = hta::encode_signature(final_signature, 2);
    const auto registration1_wire = hta::encode_registration(registration1);
    const auto registration2_wire = hta::encode_registration(registration2);
    if (!proof_wire || !signature_wire || !registration1_wire || !registration2_wire)
        throw std::runtime_error("KAT serialization failed");

    const auto digest_bytes = PublicBytes(roster->digest.begin(), roster->digest.end());
    const auto ctx = context(sid, *roster, threshold, message, masked_key, subset);
    const auto beta = hta::scalar_challenge(
        hta::transcript("NON", {hta::frame(2, ctx), hta::frame(4, aggregate->first),
                                hta::frame(4, aggregate->second)}), false);
    const PublicBytes beta_bytes(beta.begin(), beta.end());
    const auto weighted_nonce =
        must(hta::public_point_multiply(aggregate->second, beta_bytes));
    const auto nonce = must(hta::public_point_add(aggregate->first, weighted_nonce));
    const auto challenge = hta::scalar_challenge(
        hta::transcript("SIG", {hta::frame(2, digest_bytes), hta::frame(4, masked_key),
                                hta::frame_integer(threshold), hta::frame(4, nonce),
                                hta::frame(2, message)}), false);

    std::ostringstream output;
    output << "format=hta-phase3-kat-v1\n";
    output << "random_draws=" << counter << '\n';
    output << "registration_1=" << hex(*registration1_wire) << '\n';
    output << "registration_2=" << hex(*registration2_wire) << '\n';
    output << "roster_digest=" << hex(digest_bytes) << '\n';
    output << "masked_key=" << hex(masked_key) << '\n';
    output << "commitment_1_first=" << hex(first->first) << '\n';
    output << "commitment_1_second=" << hex(first->second) << '\n';
    output << "commitment_2_first=" << hex(second->first) << '\n';
    output << "commitment_2_second=" << hex(second->second) << '\n';
    output << "aggregate_first=" << hex(aggregate->first) << '\n';
    output << "aggregate_second=" << hex(aggregate->second) << '\n';
    output << "beta=" << hex(PublicBytes(beta.begin(), beta.end())) << '\n';
    output << "challenge=" << hex(PublicBytes(challenge.begin(), challenge.end())) << '\n';
    output << "response_1=" << hex(*response1) << '\n';
    output << "response_2=" << hex(*response2) << '\n';
    output << "signature_response=" << hex(signature->response) << '\n';
    output << "authorization_proof=" << hex(*proof_wire) << '\n';
    output << "signature=" << hex(*signature_wire) << '\n';
    return output.str();
}
} // namespace

int main(int argc, char **argv) {
    try {
        if (argc != 2 && argc != 4)
            throw std::runtime_error(
                "usage: phase3_kat_generator request.req [--check response.rsp]");
        const auto response = generate(argv[1]);
        if (argc == 2) {
            std::cout << response;
            return 0;
        }
        if (std::string(argv[2]) != "--check")
            throw std::runtime_error("expected --check");
        std::ifstream expected(argv[3]);
        if (!expected)
            throw std::runtime_error("cannot open KAT response");
        std::ostringstream contents;
        contents << expected.rdbuf();
        if (contents.str() != response)
            throw std::runtime_error("KAT response mismatch");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
