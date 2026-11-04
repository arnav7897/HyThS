#pragma once

#include "hta/registration.hpp"

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>

namespace hta {
struct RoundOneCommitments {
    PublicBytes first;
    PublicBytes second;
};

// Research prototype. mcl secret operations are variable-time. Replay protection is process-local
// and is lost on restart. Callers must authenticate and pin the roster digest.
class Signer final {
  public:
    Signer(std::uint64_t index, SecretScalar secret_key);
    Signer(const Signer &) = delete;
    Signer &operator=(const Signer &) = delete;

    std::optional<RoundOneCommitments> round1(const Roster &roster, const PublicBytes &sid,
                                              std::uint32_t threshold, const PublicBytes &message,
                                              const PublicBytes &masked_key,
                                              const std::vector<std::uint64_t> &subset);
    std::optional<PublicBytes> round2(const PublicBytes &sid, const PublicBytes &aggregate_first,
                                      const PublicBytes &aggregate_second);

  private:
    struct Session {
        SecretScalar first_nonce;
        SecretScalar second_nonce;
        PublicBytes context;
        PublicBytes roster_digest;
        PublicBytes masked_key;
        PublicBytes message;
        std::uint32_t threshold;
    };

    std::uint64_t index_;
    SecretScalar secret_key_;
    std::mutex mutex_;
    std::set<PublicBytes> used_sessions_;
    std::map<PublicBytes, Session> sessions_;
};
} // namespace hta
