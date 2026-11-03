#include "hta/expand_message.hpp"

#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<std::uint8_t>;

static Bytes bytes(const std::string &s) { return Bytes(s.begin(), s.end()); }

static std::string hex(const Bytes &input) {
    const char digits[] = "0123456789abcdef";
    std::string result;
    for (auto value : input) {
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 15]);
    }
    return result;
}

int main() {
    const auto dst = bytes("QUUX-V01-CS02-with-expander-SHA256-128");
    if (hex(hta::expand_message_xmd_sha256({}, dst, 32)) !=
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
        return EXIT_FAILURE;
    if (hex(hta::expand_message_xmd_sha256(bytes("abc"), dst, 32)) !=
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615")
        return EXIT_FAILURE;
    if (hex(hta::expand_message_xmd_sha256({}, dst, 128)) !=
        "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe"
        "e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18"
        "eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc"
        "c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced")
        return EXIT_FAILURE;
    const auto long_dst =
        bytes("QUUX-V01-CS02-with-expander-SHA256-128-long-DST-" + std::string(208, '1'));
    if (hex(hta::expand_message_xmd_sha256({}, long_dst, 32)) !=
        "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3")
        return EXIT_FAILURE;
    if (hta::expand_message_xmd_sha256({}, dst, 8160).size() != 8160)
        return EXIT_FAILURE;
    const auto sample = hta::expand_message_xmd_sha256(bytes("abc"), dst, 32);
    if (sample != hta::expand_message_xmd_sha256(bytes("abc"), dst, 32) ||
        sample == hta::expand_message_xmd_sha256(bytes("abc"), bytes("other domain"), 32))
        return EXIT_FAILURE;
    for (const auto length : {std::size_t{0}, std::size_t{8161}}) {
        try {
            (void)hta::expand_message_xmd_sha256({}, dst, length);
            return EXIT_FAILURE;
        } catch (const std::invalid_argument &) {
        }
    }
    return EXIT_SUCCESS;
}
