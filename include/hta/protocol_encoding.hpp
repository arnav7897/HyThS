#pragma once

#include "hta/authorization.hpp"

namespace hta {
struct RoundOneRequest {
    std::uint64_t signer_index;
    PublicBytes sid;
    PublicBytes roster_digest;
    std::uint32_t threshold;
    PublicBytes message;
    PublicBytes masked_key;
    std::vector<std::uint64_t> subset;
};

struct RoundOneResponse {
    std::uint64_t signer_index;
    PublicBytes sid;
    RoundOneCommitments commitments;
};

struct RoundTwoRequest {
    std::uint64_t signer_index;
    PublicBytes sid;
    AggregateCommitments commitments;
};

struct RoundTwoResponse {
    std::uint64_t signer_index;
    PublicBytes sid;
    PublicBytes response;
};

std::optional<PublicBytes> encode_registration(const Registration &registration);
std::optional<Registration> decode_registration(const PublicBytes &input);
std::optional<PublicBytes> encode_round_one_request(const RoundOneRequest &request);
std::optional<RoundOneRequest> decode_round_one_request(const PublicBytes &input,
                                                        std::uint32_t roster_size);
std::optional<PublicBytes> encode_round_one_response(const RoundOneResponse &response);
std::optional<RoundOneResponse> decode_round_one_response(const PublicBytes &input);
std::optional<PublicBytes> encode_round_two_request(const RoundTwoRequest &request);
std::optional<RoundTwoRequest> decode_round_two_request(const PublicBytes &input);
std::optional<PublicBytes> encode_round_two_response(const RoundTwoResponse &response);
std::optional<RoundTwoResponse> decode_round_two_response(const PublicBytes &input);

std::optional<PublicBytes> encode_authorization_proof(const AuthorizationProof &proof,
                                                      std::uint32_t roster_size);
std::optional<AuthorizationProof> decode_authorization_proof(const PublicBytes &input,
                                                             std::uint32_t roster_size);
std::optional<PublicBytes> encode_signature(const FinalSignature &signature,
                                            std::uint32_t roster_size);
std::optional<FinalSignature> decode_signature(const PublicBytes &input, std::uint32_t roster_size);
} // namespace hta
