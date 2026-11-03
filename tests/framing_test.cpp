#include "hta/framing.hpp"

#include <cstdlib>
#include <stdexcept>
#include <vector>

int main() {
    using Bytes = std::vector<std::uint8_t>;
    if (hta::frame(2, {}) != Bytes({2, 0, 0, 0, 0})) return EXIT_FAILURE;
    if (hta::frame(3, {0, 1, 255}) != Bytes({3, 0, 0, 0, 3, 0, 1, 255})) return EXIT_FAILURE;
    if (hta::frame_integer(0x0102030405060708ULL) !=
        Bytes({3, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})) return EXIT_FAILURE;
    if (hta::frame_integer(0) != Bytes({3, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0}))
        return EXIT_FAILURE;
    Bytes order{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
                0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
    if (hta::is_canonical_scalar(order) || !hta::is_canonical_scalar(Bytes(32, 0)) ||
        hta::is_canonical_scalar(Bytes(31, 0)) || hta::is_canonical_scalar(Bytes(33, 0)))
        return EXIT_FAILURE;
    --order.back();
    if (!hta::is_canonical_scalar(order)) return EXIT_FAILURE;
    order.back() += 2;
    if (hta::is_canonical_scalar(order)) return EXIT_FAILURE;
    auto indices = hta::frame_integer(1);
    const auto second = hta::frame_integer(2);
    indices.insert(indices.end(), second.begin(), second.end());
    const Bytes expected_subset{1,0,0,0,63,2,0,0,0,16,'H','T','A','-','s','e','c','p',
        '2','5','6','k','1','-','v','1',2,0,0,0,6,'S','U','B','S','E','T',6,0,0,0,26,
        3,0,0,0,8,0,0,0,0,0,0,0,1,3,0,0,0,8,0,0,0,0,0,0,0,2};
    if (hta::transcript("SUBSET", {hta::frame(6, indices)}) != expected_subset)
        return EXIT_FAILURE;
    const Bytes base_point{0x02,0x79,0xbe,0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,
        0x62,0x95,0xce,0x87,0x0b,0x07,0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,
        0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98};
    const Bytes expected_roster{1,0,0,0,88,2,0,0,0,16,'H','T','A','-','s','e','c','p',
        '2','5','6','k','1','-','v','1',2,0,0,0,6,'R','O','S','T','E','R',
        3,0,0,0,8,0,0,0,0,0,0,0,1,6,0,0,0,38,4,0,0,0,33,0x02,0x79,0xbe,
        0x66,0x7e,0xf9,0xdc,0xbb,0xac,0x55,0xa0,0x62,0x95,0xce,0x87,0x0b,0x07,
        0x02,0x9b,0xfc,0xdb,0x2d,0xce,0x28,0xd9,0x59,0xf2,0x81,0x5b,0x16,0xf8,0x17,0x98};
    if (hta::transcript("ROSTER", {hta::frame_integer(1),
                                    hta::frame(6, hta::frame(4, base_point))}) != expected_roster)
        return EXIT_FAILURE;
    if (hta::frame(1, Bytes(256, 0))[3] != 1) return EXIT_FAILURE;
    for (auto tag : {0, 7, 255}) {
        try { hta::frame(static_cast<std::uint8_t>(tag), {}); return EXIT_FAILURE; }
        catch (const std::invalid_argument&) {}
    }
    const Bytes input{2, 0, 0, 0, 2, 10, 20, 99};
    const auto view = hta::read_frame(input, 0, 2, 2);
    if (!view || view->payload_offset != 5 || view->payload_size != 2 || view->next_offset != 7)
        return EXIT_FAILURE;
    if (hta::read_frame(input, 0, 3, 2) || hta::read_frame(input, 0, 2, 1) ||
        hta::read_frame(input, 100, 2, 100) || hta::read_frame(input, 0, 7, 100))
        return EXIT_FAILURE;
    for (std::size_t n = 0; n < 7; ++n) {
        if (hta::read_frame(Bytes(input.begin(), input.begin() + n), 0, 2, 10))
            return EXIT_FAILURE;
    }
    if (hta::read_frame(Bytes{2, 255, 255, 255, 255}, 0, 2, 100)) return EXIT_FAILURE;
    if (!hta::read_frame(Bytes{9, 2, 0, 0, 0, 0}, 1, 2, 0)) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
