#include "hta/framing.hpp"
#include "hta/scalar_challenge.hpp"
#include "scalar_challenge_test.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <stdexcept>

int main() {
    const auto indices = hta::frame(
        6, {3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 2});
    const auto input = hta::transcript("SUBSET", {indices});
    const std::array<std::uint8_t, 32> expected{0x61, 0xf8, 0xd5, 0xe1, 0x6e, 0x2e, 0x98, 0xe3,
                                                0x77, 0x46, 0x3e, 0xd3, 0x12, 0x9f, 0x23, 0xe9,
                                                0x58, 0x19, 0x7b, 0x8f, 0xa8, 0xb3, 0xdb, 0x6b,
                                                0x53, 0x86, 0xae, 0x76, 0x76, 0x71, 0xf2, 0x4c};
    if (hta::scalar_challenge(input, false) != expected ||
        hta::scalar_challenge(input, true) != expected ||
        hta::scalar_challenge({}, false) == expected)
        return EXIT_FAILURE;

    unsigned int calls = 0;
    const auto rejected_then_valid = hta::testing::scalar_challenge_with_hash(
        {}, false, [&calls](const std::vector<std::uint8_t> &) {
            std::array<std::uint8_t, 32> value{};
            if (calls++ == 0)
                value.fill(0xff);
            else
                value.back() = 1;
            return value;
        });
    if (calls != 2 || rejected_then_valid.back() != 1)
        return EXIT_FAILURE;

    calls = 0;
    const auto zero_rejected = hta::testing::scalar_challenge_with_hash(
        {}, true, [&calls](const std::vector<std::uint8_t> &) {
            std::array<std::uint8_t, 32> value{};
            if (calls++ != 0)
                value.back() = 1;
            return value;
        });
    if (calls != 2 || zero_rejected.back() != 1)
        return EXIT_FAILURE;

    calls = 0;
    try {
        (void)hta::testing::scalar_challenge_with_hash(
            {}, false,
            [&calls](const std::vector<std::uint8_t> &) {
                ++calls;
                std::array<std::uint8_t, 32> value{};
                value.fill(0xff);
                return value;
            },
            std::numeric_limits<std::uint64_t>::max());
        return EXIT_FAILURE;
    } catch (const std::overflow_error &) {
    }
    if (calls != 1)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
