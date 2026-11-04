#include "hta/hash_to_curve.hpp"

#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>

static std::string hex(const std::vector<std::uint8_t> &bytes) {
    const char digits[] = "0123456789abcdef";
    std::string output;
    for (const auto byte : bytes) {
        output.push_back(digits[byte >> 4]);
        output.push_back(digits[byte & 15]);
    }
    return output;
}

int main() {
    const std::string empty = "03c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346";
    const std::string abc = "023377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b";
    const std::string long_message =
        "02bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a";
    if (hex(hta::hash_to_curve_secp256k1({})) != empty ||
        hex(hta::hash_to_curve_secp256k1({'a', 'b', 'c'})) != abc ||
        hex(hta::hash_to_curve_secp256k1({'a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4',
                                          '5', '6', '7', '8', '9'})) != long_message ||
        hta::hash_to_curve_secp256k1({'a', 'b', 'c'}) !=
            hta::hash_to_curve_secp256k1({'a', 'b', 'c'}))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
