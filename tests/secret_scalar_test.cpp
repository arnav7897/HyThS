#include "hta/secret_scalar.hpp"

#include <cstdlib>
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <utility>

int main() {
    static_assert(!std::is_copy_constructible<hta::SecretScalar>::value,
                  "secret scalar must not be copyable");
    static_assert(!std::is_copy_assignable<hta::SecretScalar>::value,
                  "secret scalar must not be copy assignable");
    static_assert(std::is_nothrow_move_constructible<hta::SecretScalar>::value,
                  "secret scalar moves must be noexcept");

    for (unsigned int i = 0; i < 64; ++i) {
        auto secret = hta::random_secret_scalar();
        if (!secret.valid())
            return EXIT_FAILURE;
        const auto original = secret.bytes();
        auto moved = std::move(secret);
        if (!moved.valid() || moved.bytes() != original)
            return EXIT_FAILURE;
        for (const auto byte : secret.bytes())
            if (byte != 0)
                return EXIT_FAILURE;
        hta::SecretScalar assigned = hta::random_secret_scalar();
        assigned = std::move(moved);
        if (!assigned.valid() || moved.valid())
            return EXIT_FAILURE;
    }

    constexpr std::array<std::uint8_t, 32> order_minus_one = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
        0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40};
    unsigned int calls = 0;
    auto sampled = hta::testing::random_secret_scalar_with_rng(
        [&calls, &order_minus_one](std::uint8_t *output, int length) {
            if (length != 32)
                return 0;
            if (calls++ == 0)
                std::fill(output, output + length, 0xff);
            else
                std::copy(order_minus_one.begin(), order_minus_one.end(), output);
            return 1;
        });
    if (calls != 2 || !sampled.valid() || sampled.bytes() != order_minus_one)
        return EXIT_FAILURE;

    calls = 0;
    sampled =
        hta::testing::random_secret_scalar_with_rng([&calls](std::uint8_t *output, int length) {
            if (length != 32)
                return 0;
            std::fill(output, output + length, 0);
            if (calls++ != 0)
                output[length - 1] = 1;
            return 1;
        });
    if (calls != 2 || !sampled.valid() || sampled.bytes().back() != 1)
        return EXIT_FAILURE;

    sampled = hta::testing::random_secret_scalar_allow_zero_with_rng(
        [](std::uint8_t *output, int length) {
            std::fill(output, output + length, 0);
            return length == 32 ? 1 : 0;
        });
    if (!sampled.valid(false) || sampled.valid())
        return EXIT_FAILURE;

    calls = 0;
    try {
        (void)hta::testing::random_secret_scalar_with_rng([&calls](std::uint8_t *, int) {
            ++calls;
            return 0;
        });
        return EXIT_FAILURE;
    } catch (const std::runtime_error &) {
    }
    if (calls != 1)
        return EXIT_FAILURE;

    calls = 0;
    try {
        (void)hta::testing::random_secret_scalar_with_rng(
            [&calls](std::uint8_t *output, int length) {
                ++calls;
                std::fill(output, output + length, 0xff);
                return 1;
            });
        return EXIT_FAILURE;
    } catch (const std::runtime_error &) {
    }
    if (calls != 128)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
