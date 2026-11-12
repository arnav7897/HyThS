#include "hta/secp256k1_public.hpp"

#include <secp256k1.h>

#include <algorithm>
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

Bytes native_msm(const secp256k1_context *ctx, const std::vector<Bytes> &points,
                 const std::vector<Bytes> &scalars) {
    if (points.empty() || points.size() != scalars.size())
        throw std::invalid_argument("invalid MSM inputs");
    std::vector<secp256k1_pubkey> products(points.size());
    std::vector<const secp256k1_pubkey *> product_ptrs;
    product_ptrs.reserve(points.size());
    for (std::size_t i = 0; i < points.size(); ++i) {
        if (!secp256k1_ec_pubkey_parse(ctx, &products[i], points[i].data(), points[i].size()) ||
            !secp256k1_ec_pubkey_tweak_mul(ctx, &products[i], scalars[i].data()))
            throw std::runtime_error("libsecp256k1 MSM term failed");
        product_ptrs.push_back(&products[i]);
    }
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, product_ptrs.data(), product_ptrs.size()))
        throw std::runtime_error("libsecp256k1 MSM aggregation failed");
    return serialize(ctx, sum);
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
        for (const unsigned terms : {1U, 4U, 16U, 64U}) {
            std::vector<Bytes> points, scalars;
            points.reserve(terms);
            scalars.reserve(terms);
            for (unsigned i = 0; i < terms; ++i) {
                points.push_back(native_generator(ctx, scalar(i + 11)));
                scalars.push_back(scalar(i + 101));
            }
            const auto expected = hta::public_msm(points, scalars);
            if (!expected || *expected != native_msm(ctx, points, scalars))
                throw std::runtime_error("backend MSM mismatch");
            const auto calls = std::max(1U, static_cast<unsigned>(iterations) / terms);
            const auto operation = std::string("msm_k") + std::to_string(terms);
            measure("mcl", operation.c_str(), calls,
                    [&](unsigned) { return hta::public_msm(points, scalars).value(); });
            measure("libsecp256k1", operation.c_str(), calls,
                    [&](unsigned) { return native_msm(ctx, points, scalars); });
        }
        secp256k1_context_destroy(ctx);
        return EXIT_SUCCESS;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
