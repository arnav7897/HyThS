#include "hta/hash_to_field.hpp"

#include <cstdlib>
#include <stdexcept>
#include <string>

static std::vector<std::uint8_t> bytes(const std::string &value) {
    return {value.begin(), value.end()};
}

static std::string hex(const std::array<std::uint8_t, 32> &value) {
    const char digits[] = "0123456789abcdef";
    std::string output;
    for (auto byte : value) {
        output.push_back(digits[byte >> 4]);
        output.push_back(digits[byte & 15]);
    }
    return output;
}

int main() {
    const auto dst = bytes("QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_");
    const auto empty = hta::hash_to_field_secp256k1({}, dst, 2);
    if (hex(empty[0]) != "6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3" ||
        hex(empty[1]) != "1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16")
        return EXIT_FAILURE;
    const auto abc = hta::hash_to_field_secp256k1(bytes("abc"), dst, 2);
    if (hex(abc[0]) != "128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61" ||
        hex(abc[1]) != "5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00" ||
        abc != hta::hash_to_field_secp256k1(bytes("abc"), dst, 2) ||
        abc == hta::hash_to_field_secp256k1(bytes("abc"), bytes("other"), 2) ||
        hta::hash_to_field_secp256k1({}, dst, 170).size() != 170)
        return EXIT_FAILURE;
    for (const auto count : {std::size_t{0}, std::size_t{171}}) {
        try {
            (void)hta::hash_to_field_secp256k1({}, dst, count);
            return EXIT_FAILURE;
        } catch (const std::invalid_argument &) {
        }
    }
    return EXIT_SUCCESS;
}
