#include "hta/protocol_encoding.hpp"
#include "hta/registration.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>

using namespace hta;
using Clock = std::chrono::steady_clock;

static std::uint64_t elapsed(Clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count();
}

int main(int argc, char **argv) {
    try {
        if (argc != 2)
            throw std::runtime_error("usage: asiaccs27_registration_bench samples");
        const auto samples = static_cast<std::uint32_t>(std::stoul(argv[1]));
        if (samples < 100 || samples > 100000)
            throw std::runtime_error("samples must be in [100, 100000]");
        const PublicBytes registry{'a','s','i','a','c','c','s','2','7','-','r','e','g'};
        constexpr std::uint32_t warmups = 10;
        for (std::uint32_t i = 0; i < samples + warmups; ++i) {
            auto key = random_secret_scalar();
            const auto index = static_cast<std::uint64_t>(i + 1);
            auto start = Clock::now();
            auto registration = create_registration(key, index, registry);
            const auto create_ns = elapsed(start);
            start = Clock::now();
            const auto valid = verify_registration(registration, registry);
            const auto verify_ns = elapsed(start);
            if (!valid)
                throw std::runtime_error("generated PoP failed verification");
            if (i >= warmups) {
                const auto wire = encode_registration(registration);
                if (!wire)
                    throw std::runtime_error("registration encoding failed");
                std::cout << "{\"sample\":" << (i - warmups)
                          << ",\"registration_ns\":" << create_ns
                          << ",\"pop_verify_ns\":" << verify_ns
                          << ",\"registration_bytes\":" << wire->size() << "}\n";
            }
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
