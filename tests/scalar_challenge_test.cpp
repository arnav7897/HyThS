#include "hta/framing.hpp"
#include "hta/scalar_challenge.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>

int main() {
    const auto indices = hta::frame(
        6, {3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 2});
    const auto input = hta::transcript("SUBSET", {indices});
    const std::array<std::uint8_t, 32> expected{0x50, 0x80, 0x23, 0x67, 0x40, 0xf6, 0xe6, 0xe3,
                                                0xc1, 0xa2, 0x1d, 0xf6, 0x6e, 0x26, 0x92, 0x56,
                                                0x3a, 0x09, 0x19, 0x66, 0x34, 0x3e, 0x86, 0xc8,
                                                0xc0, 0x9a, 0x2a, 0x23, 0xb4, 0x28, 0x58, 0xdc};
    if (hta::scalar_challenge(input, false) != expected ||
        hta::scalar_challenge(input, true) != expected ||
        hta::scalar_challenge({}, false) == expected)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
