#include "hta/protocol_encoding.hpp"

#include "hta/framing.hpp"
#include "hta/parameters.hpp"
#include "hta/secp256k1_public.hpp"

#include <algorithm>
#include <array>

namespace hta {
namespace {
constexpr std::size_t max_message = 16 * 1024 * 1024;
constexpr std::size_t max_round_one = 17 * 1024 * 1024;
constexpr std::size_t max_transport = 4096;
constexpr std::size_t max_signature = 5 * 1024 * 1024;
const PublicBytes suite{'H', 'T', 'A', '-', 's', 'e', 'c', 'p',
                        '2', '5', '6', 'k', '1', '-', 'v', '1'};

std::optional<PublicBytes> encode_message(const std::string &label,
                                          const std::vector<PublicBytes> &fields,
                                          std::size_t limit) {
    auto result = transcript(label, fields);
    if (result.size() > limit)
        return std::nullopt;
    return result;
}

std::optional<std::vector<PublicBytes>> decode_message(const PublicBytes &input,
                                                       const std::string &label,
                                                       const std::vector<std::uint8_t> &tags,
                                                       std::size_t limit) {
    if (input.size() > limit)
        return std::nullopt;
    const auto outer = read_frame(input, 0, 1, limit);
    if (!outer || outer->next_offset != input.size())
        return std::nullopt;
    PublicBytes payload(input.begin() + outer->payload_offset,
                        input.begin() + outer->payload_offset + outer->payload_size);
    std::size_t offset = 0;
    const auto suite_frame = read_frame(payload, offset, 2, 64);
    if (!suite_frame || PublicBytes(payload.begin() + suite_frame->payload_offset,
                                    payload.begin() + suite_frame->payload_offset +
                                        suite_frame->payload_size) != suite)
        return std::nullopt;
    offset = suite_frame->next_offset;
    const auto label_frame = read_frame(payload, offset, 2, 64);
    if (!label_frame ||
        PublicBytes(payload.begin() + label_frame->payload_offset,
                    payload.begin() + label_frame->payload_offset + label_frame->payload_size) !=
            PublicBytes(label.begin(), label.end()))
        return std::nullopt;
    offset = label_frame->next_offset;

    std::vector<PublicBytes> fields;
    fields.reserve(tags.size());
    for (const auto tag : tags) {
        const auto field = read_frame(payload, offset, tag, limit);
        if (!field)
            return std::nullopt;
        fields.emplace_back(payload.begin() + field->payload_offset,
                            payload.begin() + field->payload_offset + field->payload_size);
        offset = field->next_offset;
    }
    if (offset != payload.size())
        return std::nullopt;
    return fields;
}

PublicBytes integer_payload(std::uint64_t value) {
    const auto framed = frame_integer(value);
    return {framed.begin() + 5, framed.end()};
}

std::optional<std::uint64_t> parse_integer(const PublicBytes &payload) {
    if (payload.size() != 8)
        return std::nullopt;
    std::uint64_t value = 0;
    for (const auto byte : payload)
        value = (value << 8) | byte;
    return value;
}

std::optional<PublicBytes> encode_subset(const std::vector<std::uint64_t> &subset) {
    if (subset.empty() || !std::is_sorted(subset.begin(), subset.end()) ||
        std::adjacent_find(subset.begin(), subset.end()) != subset.end() || subset.front() == 0)
        return std::nullopt;
    PublicBytes payload;
    for (const auto index : subset) {
        const auto field = frame_integer(index);
        payload.insert(payload.end(), field.begin(), field.end());
    }
    return transcript("SUBSET", {frame(6, payload)});
}

std::optional<std::vector<std::uint64_t>> decode_subset(const PublicBytes &input,
                                                        std::uint32_t roster_size) {
    const auto fields = decode_message(input, "SUBSET", {6}, max_round_one);
    if (!fields)
        return std::nullopt;
    std::vector<std::uint64_t> subset;
    std::size_t offset = 0;
    const auto &payload = fields->front();
    while (offset < payload.size()) {
        const auto field = read_frame(payload, offset, 3, 8);
        if (!field || field->payload_size != 8)
            return std::nullopt;
        PublicBytes integer(payload.begin() + field->payload_offset,
                            payload.begin() + field->payload_offset + field->payload_size);
        const auto index = parse_integer(integer);
        if (!index || *index == 0 || *index > roster_size ||
            (!subset.empty() && *index <= subset.back()))
            return std::nullopt;
        subset.push_back(*index);
        offset = field->next_offset;
    }
    if (subset.empty() || subset.size() > roster_size)
        return std::nullopt;
    return subset;
}

bool valid_point(const PublicBytes &point, bool allow_identity) {
    return valid_public_point(point, allow_identity);
}

std::optional<PublicBytes> encode_proof_fields(const AuthorizationProof &proof,
                                               std::uint32_t roster_size) {
    const auto dims = dimensions(roster_size, 1);
    if (!dims || proof.vL.size() != dims->N || proof.vR.size() != dims->N ||
        !valid_point(proof.A, true) || !valid_point(proof.S, true) ||
        !valid_point(proof.Qs, true) || !valid_point(proof.T1, true) ||
        !valid_point(proof.T2, true) || !valid_public_scalar(proof.t_hat) ||
        !valid_public_scalar(proof.mu) || !valid_public_scalar(proof.tau_x) ||
        !std::all_of(proof.vL.begin(), proof.vL.end(), valid_public_scalar) ||
        !std::all_of(proof.vR.begin(), proof.vR.end(), valid_public_scalar))
        return std::nullopt;
    PublicBytes left_payload, right_payload;
    for (const auto &scalar : proof.vL) {
        const auto field = frame(5, scalar);
        left_payload.insert(left_payload.end(), field.begin(), field.end());
    }
    for (const auto &scalar : proof.vR) {
        const auto field = frame(5, scalar);
        right_payload.insert(right_payload.end(), field.begin(), field.end());
    }
    return encode_message("PROOF",
                          {frame(4, proof.A), frame(4, proof.S), frame(4, proof.Qs),
                           frame(4, proof.T1), frame(4, proof.T2), frame(6, left_payload),
                           frame(6, right_payload), frame(5, proof.t_hat), frame(5, proof.mu),
                           frame(5, proof.tau_x)},
                          max_signature);
}

std::optional<std::vector<PublicBytes>> decode_scalar_vector(const PublicBytes &payload,
                                                             std::uint32_t count) {
    std::vector<PublicBytes> result;
    result.reserve(count);
    std::size_t offset = 0;
    while (offset < payload.size()) {
        if (result.size() == count)
            return std::nullopt;
        const auto field = read_frame(payload, offset, 5, 32);
        if (!field || field->payload_size != 32)
            return std::nullopt;
        result.emplace_back(payload.begin() + field->payload_offset,
                            payload.begin() + field->payload_offset + field->payload_size);
        if (!valid_public_scalar(result.back()))
            return std::nullopt;
        offset = field->next_offset;
    }
    if (result.size() != count)
        return std::nullopt;
    return result;
}

std::optional<AuthorizationProof> decode_proof_fields(const PublicBytes &input,
                                                      std::uint32_t roster_size) {
    const auto dims = dimensions(roster_size, 1);
    if (!dims)
        return std::nullopt;
    const auto fields =
        decode_message(input, "PROOF", {4, 4, 4, 4, 4, 6, 6, 5, 5, 5}, max_signature);
    if (!fields)
        return std::nullopt;
    AuthorizationProof proof{(*fields)[0], (*fields)[1], (*fields)[2], (*fields)[3], (*fields)[4],
                             {},           {},           (*fields)[7], (*fields)[8], (*fields)[9]};
    const auto left = decode_scalar_vector((*fields)[5], dims->N);
    const auto right = decode_scalar_vector((*fields)[6], dims->N);
    if (!left || !right)
        return std::nullopt;
    proof.vL = *left;
    proof.vR = *right;
    if (!encode_proof_fields(proof, roster_size))
        return std::nullopt;
    return proof;
}
} // namespace

std::optional<PublicBytes> encode_registration(const Registration &registration) {
    if (registration.index == 0 || registration.index > 65535 ||
        !valid_point(registration.public_key, false) ||
        !valid_point(registration.proof.commitment, false) ||
        !valid_public_scalar(registration.proof.response))
        return std::nullopt;
    return encode_message("REGISTER",
                          {frame_integer(registration.index), frame(4, registration.public_key),
                           frame(4, registration.proof.commitment),
                           frame(5, registration.proof.response)},
                          max_transport);
}

std::optional<Registration> decode_registration(const PublicBytes &input) {
    const auto fields = decode_message(input, "REGISTER", {3, 4, 4, 5}, max_transport);
    if (!fields)
        return std::nullopt;
    const auto index = parse_integer((*fields)[0]);
    if (!index || *index == 0 || *index > 65535 || !valid_point((*fields)[1], false) ||
        !valid_point((*fields)[2], false) || !valid_public_scalar((*fields)[3]))
        return std::nullopt;
    return Registration{*index, (*fields)[1], ProofOfPossession{(*fields)[2], (*fields)[3]}};
}

std::optional<PublicBytes> encode_round_one_request(const RoundOneRequest &request) {
    if (request.signer_index == 0 || request.sid.empty() || request.sid.size() > 256 ||
        request.roster_digest.size() != 32 || request.threshold == 0 ||
        request.message.size() > max_message || !valid_point(request.masked_key, false) ||
        request.subset.empty() || request.subset.size() > 65535 ||
        !std::is_sorted(request.subset.begin(), request.subset.end()) ||
        std::adjacent_find(request.subset.begin(), request.subset.end()) != request.subset.end() ||
        request.subset.front() == 0 || request.subset.back() > 65535 ||
        request.threshold > request.subset.size() ||
        !std::binary_search(request.subset.begin(), request.subset.end(), request.signer_index))
        return std::nullopt;
    const auto subset = encode_subset(request.subset);
    if (!subset)
        return std::nullopt;
    return encode_message("ROUND1-REQUEST",
                          {frame_integer(request.signer_index), frame(2, request.sid),
                           frame(2, request.roster_digest), frame_integer(request.threshold),
                           frame(2, request.message), frame(4, request.masked_key),
                           frame(2, *subset)},
                          max_round_one);
}

std::optional<RoundOneRequest> decode_round_one_request(const PublicBytes &input,
                                                        std::uint32_t roster_size) {
    if (roster_size == 0 || roster_size > 65535)
        return std::nullopt;
    const auto fields =
        decode_message(input, "ROUND1-REQUEST", {3, 2, 2, 3, 2, 4, 2}, max_round_one);
    if (!fields)
        return std::nullopt;
    const auto index = parse_integer((*fields)[0]);
    const auto threshold = parse_integer((*fields)[3]);
    const auto subset = decode_subset((*fields)[6], roster_size);
    if (!index || *index == 0 || *index > roster_size || !threshold || *threshold == 0 ||
        *threshold > roster_size || (*fields)[1].empty() || (*fields)[1].size() > 256 ||
        (*fields)[2].size() != 32 || (*fields)[4].size() > max_message ||
        !valid_point((*fields)[5], false) || !subset || subset->size() < *threshold ||
        !std::binary_search(subset->begin(), subset->end(), *index))
        return std::nullopt;
    return RoundOneRequest{
        *index,       (*fields)[1], (*fields)[2], static_cast<std::uint32_t>(*threshold),
        (*fields)[4], (*fields)[5], *subset};
}

std::optional<PublicBytes> encode_round_one_response(const RoundOneResponse &response) {
    if (response.signer_index == 0 || response.signer_index > 65535 || response.sid.empty() ||
        response.sid.size() > 256 || !valid_point(response.commitments.first, false) ||
        !valid_point(response.commitments.second, false))
        return std::nullopt;
    return encode_message("ROUND1-RESPONSE",
                          {frame_integer(response.signer_index), frame(2, response.sid),
                           frame(4, response.commitments.first),
                           frame(4, response.commitments.second)},
                          max_transport);
}

std::optional<RoundOneResponse> decode_round_one_response(const PublicBytes &input) {
    const auto fields = decode_message(input, "ROUND1-RESPONSE", {3, 2, 4, 4}, max_transport);
    if (!fields)
        return std::nullopt;
    const auto index = parse_integer((*fields)[0]);
    if (!index || *index == 0 || *index > 65535 || (*fields)[1].empty() ||
        (*fields)[1].size() > 256 || !valid_point((*fields)[2], false) ||
        !valid_point((*fields)[3], false))
        return std::nullopt;
    return RoundOneResponse{*index, (*fields)[1], {(*fields)[2], (*fields)[3]}};
}

std::optional<PublicBytes> encode_round_two_request(const RoundTwoRequest &request) {
    if (request.signer_index == 0 || request.signer_index > 65535 || request.sid.empty() ||
        request.sid.size() > 256 || !valid_point(request.commitments.first, false) ||
        !valid_point(request.commitments.second, false))
        return std::nullopt;
    return encode_message("ROUND2-REQUEST",
                          {frame_integer(request.signer_index), frame(2, request.sid),
                           frame(4, request.commitments.first),
                           frame(4, request.commitments.second)},
                          max_transport);
}

std::optional<RoundTwoRequest> decode_round_two_request(const PublicBytes &input) {
    const auto fields = decode_message(input, "ROUND2-REQUEST", {3, 2, 4, 4}, max_transport);
    if (!fields)
        return std::nullopt;
    const auto index = parse_integer((*fields)[0]);
    if (!index || *index == 0 || *index > 65535 || (*fields)[1].empty() ||
        (*fields)[1].size() > 256 || !valid_point((*fields)[2], false) ||
        !valid_point((*fields)[3], false))
        return std::nullopt;
    return RoundTwoRequest{*index, (*fields)[1], {(*fields)[2], (*fields)[3]}};
}

std::optional<PublicBytes> encode_round_two_response(const RoundTwoResponse &response) {
    if (response.signer_index == 0 || response.signer_index > 65535 || response.sid.empty() ||
        response.sid.size() > 256 || !valid_public_scalar(response.response))
        return std::nullopt;
    return encode_message(
        "ROUND2-RESPONSE",
        {frame_integer(response.signer_index), frame(2, response.sid), frame(5, response.response)},
        max_transport);
}

std::optional<RoundTwoResponse> decode_round_two_response(const PublicBytes &input) {
    const auto fields = decode_message(input, "ROUND2-RESPONSE", {3, 2, 5}, max_transport);
    if (!fields)
        return std::nullopt;
    const auto index = parse_integer((*fields)[0]);
    if (!index || *index == 0 || *index > 65535 || (*fields)[1].empty() ||
        (*fields)[1].size() > 256 || !valid_public_scalar((*fields)[2]))
        return std::nullopt;
    return RoundTwoResponse{*index, (*fields)[1], (*fields)[2]};
}

std::optional<PublicBytes> encode_authorization_proof(const AuthorizationProof &proof,
                                                      std::uint32_t roster_size) {
    return encode_proof_fields(proof, roster_size);
}

std::optional<AuthorizationProof> decode_authorization_proof(const PublicBytes &input,
                                                             std::uint32_t roster_size) {
    return decode_proof_fields(input, roster_size);
}

std::optional<PublicBytes> encode_signature(const FinalSignature &signature,
                                            std::uint32_t roster_size) {
    const auto &schnorr = signature.schnorr;
    if (!valid_point(schnorr.masked_key, false) || !valid_point(schnorr.nonce, false) ||
        !valid_public_scalar(schnorr.response))
        return std::nullopt;
    const auto proof = encode_proof_fields(signature.authorization, roster_size);
    if (!proof)
        return std::nullopt;
    return encode_message("SIGNATURE",
                          {frame(4, schnorr.masked_key), frame(4, schnorr.nonce),
                           frame(5, schnorr.response), frame(2, *proof)},
                          max_signature);
}

std::optional<FinalSignature> decode_signature(const PublicBytes &input,
                                               std::uint32_t roster_size) {
    const auto fields = decode_message(input, "SIGNATURE", {4, 4, 5, 2}, max_signature);
    if (!fields || !valid_point((*fields)[0], false) || !valid_point((*fields)[1], false) ||
        !valid_public_scalar((*fields)[2]))
        return std::nullopt;
    const auto proof = decode_proof_fields((*fields)[3], roster_size);
    if (!proof)
        return std::nullopt;
    return FinalSignature{{(*fields)[0], (*fields)[1], (*fields)[2]}, *proof};
}
} // namespace hta
