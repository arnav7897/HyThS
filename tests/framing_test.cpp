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
    return EXIT_SUCCESS;
}
