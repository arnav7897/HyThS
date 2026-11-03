#include "hta/secp256k1_public.hpp"

#include <cstdlib>

int main() {
    using hta::PublicBytes;
    const PublicBytes g{0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
                        0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
                        0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    const PublicBytes two_g{0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45,
                            0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c,
                            0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5};
    const PublicBytes order{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
                            0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
    PublicBytes one(32), two(32), zero(32);
    one.back() = 1;
    two.back() = 2;
    PublicBytes inverse = g;
    inverse[0] = 3;
    PublicBytes order_minus_one = order;
    --order_minus_one.back();
    PublicBytes x_too_large(33, 0xff);
    x_too_large[0] = 2;
    PublicBytes off_curve(33, 0);
    off_curve[0] = 2;
    if (!hta::valid_public_point(g, false) || !hta::valid_public_point({0}, true) ||
        hta::valid_public_point({0}, false) || hta::valid_public_point({}, true) ||
        hta::valid_public_point(x_too_large, true) || hta::valid_public_point(off_curve, true) ||
        hta::valid_public_point({4}, true) || hta::valid_public_scalar(order) ||
        hta::valid_public_scalar({1}))
        return EXIT_FAILURE;
    if (hta::public_generator_multiply(one) != g || hta::public_generator_multiply(two) != two_g ||
        hta::public_point_add(g, g) != two_g ||
        hta::public_point_add(g, inverse) != PublicBytes{0} ||
        hta::public_point_multiply(g, zero) != PublicBytes{0} ||
        hta::public_point_add(g, {0}) != g || hta::public_scalar_add(one, one) != two ||
        hta::public_scalar_add(order_minus_one, one) != zero ||
        hta::public_generator_multiply(order_minus_one) != inverse ||
        hta::public_scalar_multiply(two, one) != two || hta::public_generator_multiply(order) ||
        hta::public_point_add(g, x_too_large) || hta::public_msm({g}, {}) ||
        hta::public_msm({g, x_too_large}, {one, one}) ||
        hta::public_msm({g, g}, {one, one}) != two_g || hta::public_msm({}, {}) != PublicBytes{0})
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
