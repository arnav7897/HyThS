#pragma once

#include "hta/signer.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace hta {
struct AggregateCommitments {
    PublicBytes first;
    PublicBytes second;
};

struct SchnorrSignature {
    PublicBytes masked_key;
    PublicBytes nonce;
    PublicBytes response;
};

// Single-process research coordinator. mcl secret operations are variable-time. The caller must
// authenticate the roster digest.
class CoordinatorSession final {
  public:
    static std::optional<CoordinatorSession>
    begin(const Roster &roster, const PublicBytes &sid, std::uint32_t threshold,
          const PublicBytes &message, std::vector<std::uint64_t> subset, SecretScalar tweak);

    CoordinatorSession(const CoordinatorSession &) = delete;
    CoordinatorSession &operator=(const CoordinatorSession &) = delete;
    CoordinatorSession(CoordinatorSession &&) noexcept = default;
    CoordinatorSession &operator=(CoordinatorSession &&) noexcept = default;

    const PublicBytes &masked_key() const noexcept { return masked_key_; }
    std::optional<AggregateCommitments>
    collect_commitments(const std::map<std::uint64_t, RoundOneCommitments> &commitments);
    // Check a signer share against the exact commitments collected by this session.
    bool verify_partial_response(std::uint64_t index, const PublicBytes &response) const;
    std::optional<SchnorrSignature>
    aggregate_responses(const std::map<std::uint64_t, PublicBytes> &responses);

  private:
    enum class State { collecting_commitments, collecting_responses, closed };
    CoordinatorSession(PublicBytes digest, std::vector<PublicBytes> roster_keys,
                       std::uint32_t threshold, PublicBytes message,
                       std::vector<std::uint64_t> subset, PublicBytes masked_key,
                       SecretScalar tweak, PublicBytes context);
    void close() noexcept;

    PublicBytes digest_;
    std::vector<PublicBytes> roster_keys_;
    std::uint32_t threshold_;
    PublicBytes message_;
    std::vector<std::uint64_t> subset_;
    PublicBytes masked_key_;
    SecretScalar tweak_;
    PublicBytes context_;
    PublicBytes nonce_;
    PublicBytes nonce_challenge_;
    std::map<std::uint64_t, RoundOneCommitments> commitments_;
    std::array<std::uint8_t, 32> challenge_{};
    State state_ = State::collecting_commitments;
};
} // namespace hta
