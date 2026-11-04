#include "hta/generator_derivation.hpp"

#include <cstdlib>
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
    return EXIT_SUCCESS;
}
