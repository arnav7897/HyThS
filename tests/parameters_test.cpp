#include "hta/parameters.hpp"

#include <cstdlib>

int main() {
    if (hta::dimensions(0, 1) || hta::dimensions(1, 0) || hta::dimensions(1, 2) ||
        hta::dimensions(65536, 1))
        return EXIT_FAILURE;
    for (std::uint32_t n = 1; n <= 65535; ++n) {
        const auto d = hta::dimensions(n, n);
        if (!d || !(n < (1u << d->ell)) || !(n >= (1u << (d->ell - 1))) || d->N != n + d->ell + 1 ||
            d->generators != 2 * d->N + 1 || !hta::dimensions(n, 1) || hta::dimensions(n, n + 1))
            return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
