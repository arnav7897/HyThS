#pragma once

#include "hta/registration.hpp"

#include <cstddef>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <thread>

namespace hta {
struct RoundOneCommitments {
    PublicBytes first;
    PublicBytes second;
};

// Research prototype. mcl secret operations are variable-time. Replay protection is process-local
// and is lost on restart. Used IDs remain until process exit; once capacity is full, new sessions
// are rejected. Callers must authenticate and pin the roster digest.
class Signer final {
  public:
    static constexpr std::size_t maximum_remembered_sessions = 65536;

    // Nonzero timeout enables one cleanup thread per signer; zero disables automatic expiry.
    // Cleanup may wait for an in-flight signer operation; late Round 2 requests reject.
    Signer(std::uint64_t index, SecretScalar secret_key,
           std::size_t max_used_sessions = maximum_remembered_sessions,
           std::chrono::milliseconds session_timeout = std::chrono::milliseconds::zero());
    ~Signer();
    Signer(const Signer &) = delete;
    Signer &operator=(const Signer &) = delete;

    std::optional<RoundOneCommitments> round1(const Roster &roster, const PublicBytes &sid,
                                              std::uint32_t threshold, const PublicBytes &message,
                                              const PublicBytes &masked_key,
                                              const std::vector<std::uint64_t> &subset);
    std::optional<PublicBytes> round2(const PublicBytes &sid, const PublicBytes &aggregate_first,
                                      const PublicBytes &aggregate_second);
    // Cancel a live session and retain its spent session ID.
    bool cancel(const PublicBytes &sid);

  private:
    struct Session {
        SecretScalar first_nonce;
        SecretScalar second_nonce;
        PublicBytes context;
        PublicBytes roster_digest;
        PublicBytes masked_key;
        PublicBytes message;
        std::uint32_t threshold;
        std::chrono::steady_clock::time_point expires;
    };

    std::uint64_t index_;
    SecretScalar secret_key_;
    const std::size_t max_used_sessions_;
    std::mutex mutex_;
    const std::chrono::milliseconds session_timeout_;
    std::condition_variable timeout_changed_;
    bool stopping_ = false;
    std::thread timeout_worker_;
    std::set<PublicBytes> used_sessions_;
    std::map<PublicBytes, Session> sessions_;
};
} // namespace hta
