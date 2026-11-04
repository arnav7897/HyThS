#include "hta/protocol_encoding.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace {
using Bytes = hta::PublicBytes;
using Vectors = std::map<std::string, Bytes>;

Bytes hex_bytes(const std::string &hex) {
    if (hex.size() % 2 != 0)
        return {};
    Bytes result;
    result.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        try {
            result.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        } catch (...) {
            return {};
        }
    }
    return result;
}

Vectors load_vectors() {
    std::ifstream input(HTA_VECTOR_FILE);
    Vectors result;
    std::string line;
    while (std::getline(input, line)) {
        const auto separator = line.find('\t');
        if (separator == std::string::npos ||
            !result.emplace(line.substr(0, separator), hex_bytes(line.substr(separator + 1)))
                 .second)
            return {};
    }
    return result;
}

bool collect_frames(const Bytes &input, std::size_t begin, std::size_t end,
                    std::vector<std::size_t> &headers) {
    auto offset = begin;
    while (offset < end) {
        if (end - offset < 5 || input[offset] < 1 || input[offset] > 6)
            return false;
        const auto tag = input[offset];
        std::uint32_t size = 0;
        for (std::size_t i = 1; i <= 4; ++i)
            size = (size << 8) | input[offset + i];
        const auto payload = offset + 5;
        if (size > end - payload)
            return false;
        const auto payload_end = payload + size;
        headers.push_back(offset);
        if ((tag == 1 || tag == 6 || (tag == 2 && payload < payload_end && input[payload] == 1)) &&
            !collect_frames(input, payload, payload_end, headers))
            return false;
        offset = payload_end;
    }
    return offset == end;
}

void write_length(Bytes &input, std::size_t header, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i)
        input[header + 1 + i] = static_cast<std::uint8_t>(value >> (24 - 8 * i));
}

template <class Decode, class Encode>
bool malformed_corpus(const Bytes &wire, Decode decode, Encode encode) {
    const auto decoded = decode(wire);
    const auto canonical = decoded ? encode(*decoded) : std::nullopt;
    if (!canonical || *canonical != wire)
        return false;

    for (std::size_t size = 0; size < wire.size(); ++size) {
        const Bytes truncated(wire.begin(), wire.begin() + size);
        if (decode(truncated))
            return false;
    }
    auto trailing = wire;
    trailing.push_back(0);
    auto wrong_tag = wire;
    wrong_tag.front() = 0;
    auto overflowing_length = wire;
    std::fill(overflowing_length.begin() + 1, overflowing_length.begin() + 5, 0xff);
    auto wrong_suite = wire;
    wrong_suite[10] ^= 1;
    auto wrong_label = wire;
    wrong_label[31] ^= 1;
    if (decode(trailing) || decode(wrong_tag) || decode(overflowing_length) ||
        decode(wrong_suite) || decode(wrong_label))
        return false;

    std::vector<std::size_t> headers;
    if (!collect_frames(wire, 0, wire.size(), headers))
        return false;
    for (const auto header : headers) {
        auto bad_tag = wire;
        bad_tag[header] = 0;
        auto bad_length = wire;
        std::fill(bad_length.begin() + header + 1, bad_length.begin() + header + 5, 0xff);
        if (decode(bad_tag) || decode(bad_length))
            return false;

        const auto tag = wire[header];
        std::uint32_t payload_size = 0;
        for (std::size_t i = 1; i <= 4; ++i)
            payload_size = (payload_size << 8) | wire[header + i];
        if (tag == 3 || tag == 4 || tag == 5) {
            auto invalid_payload = wire;
            std::fill(invalid_payload.begin() + header + 5,
                      invalid_payload.begin() + header + 5 + payload_size, tag == 4 ? 0 : 0xff);
            if (decode(invalid_payload))
                return false;
        }

        std::uint32_t size = 0;
        for (std::size_t i = 1; i <= 4; ++i)
            size = (size << 8) | wire[header + i];
        for (const auto changed : {size == 0 ? size + 1 : size - 1, size + 1}) {
            auto off_by_one = wire;
            write_length(off_by_one, header, changed);
            if (decode(off_by_one))
                return false;
        }
    }
    return true;
}
} // namespace

int main() {
    const auto vectors = load_vectors();
    if (vectors.size() != 7)
        return 1;
    const Bytes generator{0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
                          0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
                          0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
    const Bytes zero(32, 0);
    const hta::Registration registration{1, generator, {generator, zero}};
    const hta::RoundOneRequest round_one_request{1, {'s'}, zero, 1, {'m'}, generator, {1}};
    const hta::RoundOneResponse round_one_response{1, {'s'}, {generator, generator}};
    const hta::RoundTwoRequest round_two_request{1, {'s'}, {generator, generator}};
    const hta::RoundTwoResponse round_two_response{1, {'s'}, zero};
    const hta::AuthorizationProof proof{
        generator,          generator,          generator, generator, generator,
        {zero, zero, zero}, {zero, zero, zero}, zero,      zero,      zero};
    const hta::FinalSignature signature{{generator, generator, zero}, proof};

    const auto registration_wire = hta::encode_registration(registration);
    const auto round_one_request_wire = hta::encode_round_one_request(round_one_request);
    const auto round_one_response_wire = hta::encode_round_one_response(round_one_response);
    const auto round_two_request_wire = hta::encode_round_two_request(round_two_request);
    const auto round_two_response_wire = hta::encode_round_two_response(round_two_response);
    const auto proof_wire = hta::encode_authorization_proof(proof, 1);
    const auto signature_wire = hta::encode_signature(signature, 1);
    if (!registration_wire || *registration_wire != vectors.at("registration") ||
        !round_one_request_wire || *round_one_request_wire != vectors.at("round_one_request") ||
        !round_one_response_wire || *round_one_response_wire != vectors.at("round_one_response") ||
        !round_two_request_wire || *round_two_request_wire != vectors.at("round_two_request") ||
        !round_two_response_wire || *round_two_response_wire != vectors.at("round_two_response") ||
        !proof_wire || *proof_wire != vectors.at("authorization_proof") || !signature_wire ||
        *signature_wire != vectors.at("signature"))
        return 1;

    if (!malformed_corpus(vectors.at("registration"), hta::decode_registration,
                          hta::encode_registration) ||
        !malformed_corpus(
            vectors.at("round_one_request"),
            [](const Bytes &bytes) { return hta::decode_round_one_request(bytes, 1); },
            hta::encode_round_one_request) ||
        !malformed_corpus(vectors.at("round_one_response"), hta::decode_round_one_response,
                          hta::encode_round_one_response) ||
        !malformed_corpus(vectors.at("round_two_request"), hta::decode_round_two_request,
                          hta::encode_round_two_request) ||
        !malformed_corpus(vectors.at("round_two_response"), hta::decode_round_two_response,
                          hta::encode_round_two_response) ||
        !malformed_corpus(
            vectors.at("authorization_proof"),
            [](const Bytes &bytes) { return hta::decode_authorization_proof(bytes, 1); },
            [](const hta::AuthorizationProof &value) {
                return hta::encode_authorization_proof(value, 1);
            }) ||
        !malformed_corpus(
            vectors.at("signature"),
            [](const Bytes &bytes) { return hta::decode_signature(bytes, 1); },
            [](const hta::FinalSignature &value) { return hta::encode_signature(value, 1); }))
        return 1;
    return 0;
}
