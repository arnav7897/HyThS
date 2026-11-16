#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);

int main() {
    const std::array<std::size_t, 8> boundary_sizes{0, 1, 2, 7, 8, 31, 32, 255};
    for (const auto size : boundary_sizes) {
        std::vector<std::uint8_t> input(size, 0);
        (void)LLVMFuzzerTestOneInput(input.data(), input.size());
        std::fill(input.begin(), input.end(), 0xff);
        (void)LLVMFuzzerTestOneInput(input.data(), input.size());
    }

    std::uint32_t state = 0x27a51c5d;
    for (std::size_t run = 0; run < 4096; ++run) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        const auto size = static_cast<std::size_t>(state % 4097);
        std::vector<std::uint8_t> input(size);
        for (auto &byte : input) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            byte = static_cast<std::uint8_t>(state);
        }
        (void)LLVMFuzzerTestOneInput(input.data(), input.size());
    }
    return 0;
}
