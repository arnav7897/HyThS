#include "hta/secret_group.hpp"

#include "hta/secp256k1_public.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstdint>
#include <vector>

static hta::SecretScalar scalar(std::uint8_t value) {
    return hta::testing::random_secret_scalar_with_rng([value](std::uint8_t *output, int length) {
        std::fill(output, output + length, 0);
        output[length - 1] = value;
        return 1;
    });
}

static hta::PublicBytes bytes(const hta::SecretScalar &value) {
    return {value.bytes().begin(), value.bytes().end()};
}

int main() {
    const auto two = scalar(2);
    const auto three = scalar(3);
    const auto five = hta::secret_scalar_add(two, three);
    const auto six = hta::secret_scalar_multiply(two, three);
    if (!five.valid() || !six.valid() ||
        bytes(five) != *hta::public_scalar_add(bytes(two), bytes(three)) ||
        bytes(six) != *hta::public_scalar_multiply(bytes(two), bytes(three)))
        return EXIT_FAILURE;

    hta::PublicBytes scalar_one(32, 0);
    scalar_one.back() = 1;
    const auto generator = hta::public_generator_multiply(scalar_one);
    if (!generator)
        return EXIT_FAILURE;
    const auto secret_fixed = hta::secret_generator_multiply(two);
    const auto public_fixed = hta::public_generator_multiply(bytes(two));
    const auto secret_variable = hta::secret_point_multiply(*generator, three);
    const auto public_variable = hta::public_point_multiply(*generator, bytes(three));
    if (!public_fixed || !public_variable || secret_fixed != *public_fixed ||
        secret_variable != *public_variable)
        return EXIT_FAILURE;

    constexpr std::array<std::uint8_t, 32> order_minus_one = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
        0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40};
    const auto minus_one = hta::testing::random_secret_scalar_with_rng(
        [&order_minus_one](std::uint8_t *output, int length) {
            std::copy(order_minus_one.begin(), order_minus_one.end(), output);
            return length == 32 ? 1 : 0;
        });
    const auto one = scalar(1);
    const auto zero = hta::secret_scalar_add(minus_one, one);
    if (!zero.valid(false) || zero.valid() ||
        hta::secret_point_multiply(*generator, zero) != hta::PublicBytes{0})
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
