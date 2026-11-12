#include "hta/generator_derivation.hpp"
#include "hta/parameters.hpp"
#include "hta/secp256k1_public.hpp"

#include <mcl/g1_def.hpp>
#include <mcl/window_method.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
using Bytes = hta::PublicBytes;
using Clock = std::chrono::steady_clock;
using Table = mcl::fp::WindowMethod<mcl::G1>;
constexpr std::size_t window_size = 4;

Bytes scalar(std::uint64_t value) {
    Bytes result(32, 0);
    for (std::size_t i = 0; i < 8; ++i) {
        result[31 - i] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
    return result;
}

mcl::G1 decode_point(const Bytes &encoded) {
    mcl::G1 point;
    if (encoded.size() != 33 || (encoded[0] != 2 && encoded[0] != 3))
        throw std::runtime_error("invalid derived point");
    std::array<std::uint8_t, 33> little{};
    little[0] = encoded[0];
    std::reverse_copy(encoded.begin() + 1, encoded.end(), little.begin() + 1);
    if (point.deserialize(little.data(), little.size()) != little.size() || point.isZero() ||
        !point.isValid())
        throw std::runtime_error("mcl point decode failed");
    return point;
}

mcl::Fr decode_scalar(const Bytes &encoded) {
    mcl::Fr value;
    const Bytes little(encoded.rbegin(), encoded.rend());
    if (value.deserialize(little.data(), little.size()) != little.size())
        throw std::runtime_error("mcl scalar decode failed");
    return value;
}

Bytes encode_point(const mcl::G1 &point) {
    if (point.isZero())
        return {0};
    std::array<std::uint8_t, 33> little{};
    if (point.serialize(little.data(), little.size()) != little.size())
        throw std::runtime_error("mcl point encode failed");
    Bytes result{little[0]};
    result.insert(result.end(), little.rbegin(), little.rend() - 1);
    return result;
}

std::uint64_t elapsed_ns(Clock::time_point start) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count());
}

void run(std::uint32_t n) {
    mcl::initCurve<mcl::G1>(MCL_SECP256K1);
    const auto dims = hta::dimensions(n, 1);
    if (!dims)
        throw std::runtime_error("invalid roster dimension");
    constexpr std::size_t sample_count = 9;
    const Bytes context{'p', 'r', 'o', 'o', 'f', '-', 't', 'a', 'b', 'l', 'e'};

    std::vector<Bytes> encoded_bases;
    encoded_bases.reserve(2 * dims->N + 1 + n);
    for (std::uint32_t i = 1; i <= 2 * dims->N + 1; ++i)
        encoded_bases.push_back(hta::derive_generator_secp256k1(context, dims->N, i));
    for (std::uint32_t i = 0; i < n; ++i)
        encoded_bases.push_back(*hta::public_generator_multiply(scalar(i + 1)));

    std::vector<Bytes> scalars;
    std::vector<mcl::Fr> field_scalars;
    std::vector<mcl::G1> points;
    scalars.reserve(encoded_bases.size());
    field_scalars.reserve(encoded_bases.size());
    points.reserve(encoded_bases.size());
    for (std::size_t i = 0; i < encoded_bases.size(); ++i) {
        scalars.push_back(scalar(i + 101));
        field_scalars.push_back(decode_scalar(scalars.back()));
        points.push_back(decode_point(encoded_bases[i]));
    }

    std::vector<Table> tables(points.size());
    const auto setup_start = Clock::now();
    std::size_t table_bytes = 0;
    for (std::size_t i = 0; i < points.size(); ++i) {
        tables[i].init(points[i], 256, window_size);
        table_bytes += tables[i].tbl_.size() * sizeof(mcl::G1);
    }
    const auto table_setup_ns = elapsed_ns(setup_start);

    const auto expected = hta::public_msm(encoded_bases, scalars);
    if (!expected)
        throw std::runtime_error("mcl MSM failed");
    mcl::G1 combined;
    for (std::size_t i = 0; i < tables.size(); ++i) {
        mcl::G1 product;
        tables[i].mul(product, field_scalars[i]);
        mcl::G1 direct;
        mcl::G1::mul(direct, points[i], field_scalars[i]);
        if (encode_point(product) != encode_point(direct))
            throw std::runtime_error("single-base fixed table mismatch at " + std::to_string(i));
        mcl::G1::add(combined, combined, product);
    }
    if (encode_point(combined) != *expected)
        throw std::runtime_error("table and MSM results differ: table=" +
                                 std::to_string(encode_point(combined).size()) + " bytes, msm=" +
                                 std::to_string(expected->size()) + " bytes");

    std::array<std::uint64_t, sample_count> table_samples{}, msm_samples{};
    for (std::size_t sample = 0; sample < sample_count; ++sample) {
        combined.clear();
        auto start = Clock::now();
        for (std::size_t i = 0; i < tables.size(); ++i) {
            mcl::G1 product;
            tables[i].mul(product, field_scalars[i]);
            mcl::G1::add(combined, combined, product);
        }
        table_samples[sample] = elapsed_ns(start);
        start = Clock::now();
        if (!hta::public_msm(encoded_bases, scalars))
            throw std::runtime_error("mcl MSM failed during timing");
        msm_samples[sample] = elapsed_ns(start);
    }

    std::cout << "{\"n\":" << n << ",\"N\":" << dims->N << ",\"base_count\":"
              << points.size() << ",\"window\":" << window_size << ",\"table_bytes\":"
              << table_bytes << ",\"table_setup_ns\":" << table_setup_ns
              << ",\"table_sum_ns\":[";
    for (std::size_t i = 0; i < sample_count; ++i)
        std::cout << (i ? "," : "") << table_samples[i];
    std::cout << "],\"mcl_msm_ns\":[";
    for (std::size_t i = 0; i < sample_count; ++i)
        std::cout << (i ? "," : "") << msm_samples[i];
    std::cout << "]}\n";
}
} // namespace

int main(int argc, char **argv) {
    try {
        const auto n = argc == 2 ? static_cast<std::uint32_t>(std::stoul(argv[1])) : 64;
        if (n == 0 || n > 4096)
            throw std::invalid_argument("n must be between 1 and 4096");
        run(n);
        return EXIT_SUCCESS;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
