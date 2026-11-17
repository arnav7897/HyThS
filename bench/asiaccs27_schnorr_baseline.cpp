#include "hta/framing.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"
#include "hta/secret_scalar.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>

using namespace hta;
using Clock = std::chrono::steady_clock;

static std::uint64_t elapsed(Clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count();
}

static PublicBytes neg(const PublicBytes &value) {
    PublicBytes zero(32, 0);
    auto out = public_scalar_subtract(zero, value);
    if (!out)
        throw std::runtime_error("scalar negation failed");
    return *out;
}

int main(int argc, char **argv) {
    try {
        if (argc != 2)
            throw std::runtime_error("usage: asiaccs27_schnorr_baseline samples");
        const auto samples = static_cast<std::uint32_t>(std::stoul(argv[1]));
        if (samples < 100 || samples > 100000)
            throw std::runtime_error("samples must be in [100, 100000]");
        const PublicBytes message(32, 0x42);
        PublicBytes one(32, 0);
        one.back() = 1;
        const auto G = *public_generator_multiply(one);
        constexpr std::uint32_t warmups = 10;
        for (std::uint32_t i = 0; i < samples + warmups; ++i) {
            auto key = random_secret_scalar();
            const auto public_key = secret_generator_multiply(key);
            const auto sign_start = Clock::now();
            auto nonce = random_secret_scalar();
            const auto R = secret_generator_multiply(nonce);
            const auto challenge_input = transcript(
                "PLAIN-SCHNORR",
                {frame(4, public_key), frame(4, R), frame(2, message)});
            const auto c_array = scalar_challenge(challenge_input, false);
            const auto c = SecretScalar::from_canonical(c_array);
            auto response = secret_scalar_add(nonce, secret_scalar_multiply(c, key));
            const auto sign_ns = elapsed(sign_start);

            const PublicBytes response_bytes(response.bytes().begin(), response.bytes().end());
            const auto verify_start = Clock::now();
            const auto verifier_input = transcript(
                "PLAIN-SCHNORR",
                {frame(4, public_key), frame(4, R), frame(2, message)});
            const auto verifier_c = scalar_challenge(verifier_input, false);
            const PublicBytes challenge_bytes(verifier_c.begin(), verifier_c.end());
            const auto valid = public_msm({G, R, public_key},
                                          {response_bytes, neg(one), neg(challenge_bytes)});
            const auto verify_ns = elapsed(verify_start);
            if (!valid || *valid != PublicBytes{0})
                throw std::runtime_error("plain Schnorr signature failed verification");

            if (i >= warmups)
                std::cout << "{\"sample\":" << (i - warmups) << ",\"sign_ns\":" << sign_ns
                          << ",\"verify_ns\":" << verify_ns
                          << ",\"signature_payload_bytes\":" << (R.size() + response_bytes.size())
                          << "}\n";
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
