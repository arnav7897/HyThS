#include "hta/authorization.hpp"
#include "hta/protocol_encoding.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

hta::PublicBytes generator() {
    return {0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
            0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
            0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
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

    const auto signature = hta::decode_signature(input, 16);
    if (signature) {
        hta::Roster roster{{generator()}, {}};
        (void)hta::verify_signature(roster, {}, 1, {}, *signature);
    }
    return 0;
}
