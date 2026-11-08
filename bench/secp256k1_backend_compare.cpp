#include "hta/secp256k1_public.hpp"

#include <secp256k1.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes = hta::PublicBytes;
using Clock = std::chrono::steady_clock;

Bytes scalar(unsigned i) {
    Bytes x(32, 0x53);
    x[28] = static_cast<std::uint8_t>(i >> 24);
    x[29] = static_cast<std::uint8_t>(i >> 16);
    x[30] = static_cast<std::uint8_t>(i >> 8);
    x[31] = static_cast<std::uint8_t>(i);
    return x;
}

Bytes serialize(const secp256k1_context *ctx, const secp256k1_pubkey &point) {
    Bytes output(33);
    std::size_t length = output.size();
    if (!secp256k1_ec_pubkey_serialize(ctx, output.data(), &length, &point,
                                       SECP256K1_EC_COMPRESSED) ||
        length != output.size())
        throw std::runtime_error("libsecp256k1 serialization failed");
    return output;
}

Bytes native_generator(const secp256k1_context *ctx, const Bytes &x) {
    secp256k1_pubkey point;
    if (!secp256k1_ec_pubkey_create(ctx, &point, x.data()))
        throw std::runtime_error("libsecp256k1 generator multiplication failed");
    return serialize(ctx, point);
}

Bytes native_point(const secp256k1_context *ctx, const Bytes &input, const Bytes &x) {
    secp256k1_pubkey point;
    if (!secp256k1_ec_pubkey_parse(ctx, &point, input.data(), input.size()) ||
        !secp256k1_ec_pubkey_tweak_mul(ctx, &point, x.data()))
        throw std::runtime_error("libsecp256k1 point multiplication failed");
    return serialize(ctx, point);
}

template <typename Op>
void measure(const char *backend, const char *operation, unsigned iterations, Op fn) {
    for (unsigned i = 0; i < 32; ++i)
        (void)fn(i);
    std::cout << "{\"backend\":\"" << backend << "\",\"operation\":\"" << operation
              << "\",\"iterations_per_sample\":" << iterations << ",\"samples_total_ns\":[";
    for (unsigned sample = 0; sample < 5; ++sample) {
        const auto start = Clock::now();
        for (unsigned i = 0; i < iterations; ++i)
            (void)fn(i);
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start);
        std::cout << (sample ? "," : "") << elapsed.count();
    }
    std::cout << "]}\n";
}
} // namespace

int main(int argc, char **argv) {
    try {
        const auto iterations = argc == 2 ? std::stoul(argv[1]) : 1000;
        if (!iterations || iterations > 1000000)
            throw std::invalid_argument("bad iteration count");
        auto *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!ctx)
            throw std::runtime_error("libsecp256k1 context creation failed");
        const auto base = native_generator(ctx, scalar(5));
        for (unsigned i = 0; i < 100; ++i) {
            auto x = scalar(i + 1);
            auto g = hta::public_generator_multiply(x);
            auto p = hta::public_point_multiply(base, x);
            if (!g || !p || *g != native_generator(ctx, x) || *p != native_point(ctx, base, x))
                throw std::runtime_error("backend mismatch");
        }
        measure("mcl", "generator_mul", iterations,
                [&](unsigned i) { return hta::public_generator_multiply(scalar(i + 1)).value(); });
        measure("libsecp256k1", "generator_mul", iterations,
                [&](unsigned i) { return native_generator(ctx, scalar(i + 1)); });
        measure("mcl", "variable_mul", iterations, [&](unsigned i) {
            return hta::public_point_multiply(base, scalar(i + 1)).value();
        });
        measure("libsecp256k1", "variable_mul", iterations,
                [&](unsigned i) { return native_point(ctx, base, scalar(i + 1)); });
        secp256k1_context_destroy(ctx);
        return EXIT_SUCCESS;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
