#include "hta/hash_to_curve.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secp256k1_public.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
using Bytes = hta::PublicBytes;

Bytes scalar(std::uint8_t value) {
    Bytes result(32, 0);
    result.back() = value;
    return result;
}

template <typename Operation>
void measure(const char *name, std::size_t iterations, Operation operation) {
    constexpr std::size_t sample_count = 9;
    for (std::size_t i = 0; i < iterations / 10 + 1; ++i) operation();
    std::array<std::uint64_t, sample_count> samples{};
    std::size_t output_size = 0;
    for (auto &sample : samples) {
        const auto start = Clock::now();
        for (std::size_t i = 0; i < iterations; ++i) output_size = operation();
        sample = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count());
    }
    auto sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    std::cout << "{\"name\":\"" << name << "\",\"iterations_per_sample\":" << iterations
              << ",\"samples_total_ns\":[";
    for (std::size_t i = 0; i < samples.size(); ++i)
        std::cout << (i ? "," : "") << samples[i];
    std::cout << "],\"median_ns_per_op\":" << sorted[sample_count / 2] / iterations
              << ",\"output_bytes\":" << output_size << "}\n";
}

Bytes require(std::optional<Bytes> result) {
    if (!result) throw std::runtime_error("primitive operation rejected benchmark input");
    return std::move(*result);
}
} // namespace

int main(int argc, char **argv) {
    try {
        const std::size_t iterations = argc > 1 ? std::stoul(argv[1]) : 1000;
        if (iterations == 0) throw std::invalid_argument("iterations must be positive");
        const Bytes one = scalar(1), two = scalar(2), three = scalar(3);
        const Bytes generator = require(hta::public_generator_multiply(one));
        const std::vector<std::uint8_t> message{'p', 'h', 'a', 's', 'e', '-', '2'};
        const std::vector<std::uint8_t> transcript{'b', 'e', 'n', 'c', 'h', '-', 'e', '1'};

        measure("secp256k1_generator_mul", iterations, [&] {
            return require(hta::public_generator_multiply(two)).size();
        });
        measure("secp256k1_variable_mul", iterations, [&] {
            return require(hta::public_point_multiply(generator, two)).size();
        });
        measure("secp256k1_hash_to_scalar", iterations, [&] {
            const auto output = hta::scalar_challenge(transcript, false);
            return output.size();
        });
        measure("secp256k1_hash_to_curve", iterations, [&] {
            return hta::hash_to_curve_secp256k1(message).size();
        });
        for (const std::size_t count : {1U, 8U, 32U, 128U}) {
            std::vector<Bytes> points(count, generator);
            std::vector<Bytes> scalars;
            scalars.reserve(count);
            for (std::size_t i = 0; i < count; ++i)
                scalars.push_back(scalar(static_cast<std::uint8_t>(i % 251 + 1)));
            const std::string label = "secp256k1_msm_" + std::to_string(count);
            measure(label.c_str(), iterations, [&] {
                return require(hta::public_msm(points, scalars)).size();
            });
        }
        return EXIT_SUCCESS;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
