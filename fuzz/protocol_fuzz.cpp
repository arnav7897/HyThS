#include "hta/authorization.hpp"
#include "hta/protocol_encoding.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

hta::SecretScalar secret(std::uint8_t value) {
    std::array<std::uint8_t, 32> encoded{};
    encoded.back() = value;
    return hta::SecretScalar::from_canonical(encoded);
}

const std::optional<hta::Roster> &fuzz_roster() {
    static const auto roster = [] {
        const hta::PublicBytes registry{'r', 'e', 'g', '-', 'k', 'a', 't'};
        const auto first = hta::create_registration(secret(7), 1, registry);
        const auto second = hta::create_registration(secret(11), 2, registry);
        return hta::build_roster({first, second}, registry);
    }();
    return roster;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
    hta::PublicBytes input;
    if (size != 0)
        input.assign(data, data + size);

    (void)hta::decode_registration(input);
    (void)hta::decode_round_one_request(input, 16);
    (void)hta::decode_round_one_response(input);
    (void)hta::decode_round_two_request(input);
    (void)hta::decode_round_two_response(input);
    (void)hta::decode_authorization_proof(input, 16);

    const auto signature = hta::decode_signature(input, 2);
    if (signature && fuzz_roster())
        (void)hta::verify_signature(*fuzz_roster(), {'g', 'e', 'n', '-', 'k', 'a', 't'}, 2,
                                    {'k', 'a', 't', '-', 'm', 's', 'g'}, *signature);
    return 0;
}
