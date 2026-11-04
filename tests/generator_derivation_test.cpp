#include "hta/generator_derivation.hpp"
#include "hta/framing.hpp"
#include "generator_derivation_test.hpp"

#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <utility>

int main() {
    const hta::PublicBytes context{'r', 'o', 's', 't', 'e', 'r', '-', 'c', 'o', 'n', 'f', 'i', 'g'};
    const auto first = hta::derive_generator_secp256k1(context, 4, 1);
    if (first.size() != 33 || (first[0] != 2 && first[0] != 3) ||
        !hta::valid_public_point(first, false) ||
        hta::derive_generator_secp256k1(context, 4, 1) != first ||
        hta::derive_generator_secp256k1(context, 4, 2) == first ||
        hta::derive_generator_secp256k1({'o', 't', 'h', 'e', 'r'}, 4, 1) == first ||
        hta::derive_generator_secp256k1(context, 5, 1) == first)
        return EXIT_FAILURE;

    for (const auto params :
         {std::pair<std::uint32_t, std::uint32_t>{0, 1}, {4, 0}, {4, 10}, {65553, 1}}) {
        try {
            (void)hta::derive_generator_secp256k1(context, params.first, params.second);
            return EXIT_FAILURE;
        } catch (const std::invalid_argument &) {
        }
    }

    const hta::PublicBytes generator{2,    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                                     0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02,
                                     0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
                                     0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    const hta::PublicBytes dst{'H', 'T', 'A', '-', 'v', '1', '-', 's', 'e', 'c', 'p',
                               '2', '5', '6', 'k', '1', '-', 'H', 'g', 'e', 'n'};
    unsigned int calls = 0;
    hta::PublicBytes original_input, retry_input;
    const auto retried = hta::testing::derive_generator_with_hash(
        context, 4, 1,
        [&calls, &original_input, &retry_input, &dst, &generator](const hta::PublicBytes &input,
                                                                  const hta::PublicBytes &domain) {
            if (domain != dst)
                return hta::PublicBytes{};
            if (calls++ == 0) {
                original_input = input;
                return hta::PublicBytes{0};
            }
            retry_input = input;
            return generator;
        });
    const auto expected_retry =
        hta::transcript("GEN-RETRY", {hta::frame(2, original_input), hta::frame_integer(1)});
    if (retried != generator || calls != 2 || retry_input != expected_retry)
        return EXIT_FAILURE;

    calls = 0;
    try {
        (void)hta::testing::derive_generator_with_hash(
            context, 4, 1,
            [&calls](const hta::PublicBytes &, const hta::PublicBytes &) {
                ++calls;
                return hta::PublicBytes{0};
            },
            std::numeric_limits<std::uint64_t>::max());
        return EXIT_FAILURE;
    } catch (const std::overflow_error &) {
    }
    if (calls != 2)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
