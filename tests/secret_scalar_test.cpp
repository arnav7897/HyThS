#include "hta/secret_scalar.hpp"

#include <cstdlib>
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
    return EXIT_SUCCESS;
}
