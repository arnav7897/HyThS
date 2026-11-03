#include "hta/framing.hpp"

#include <cstdlib>
#include <stdexcept>
#include <vector>

int main() {
    using Bytes = std::vector<std::uint8_t>;
    if (hta::frame(2, {}) != Bytes({2, 0, 0, 0, 0})) return EXIT_FAILURE;
    if (hta::frame(3, {0, 1, 255}) != Bytes({3, 0, 0, 0, 3, 0, 1, 255})) return EXIT_FAILURE;
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
