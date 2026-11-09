#include "hta/signer.hpp"

#include "hta/framing.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secret_group.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <utility>

#include <openssl/evp.h>

namespace hta {
namespace {
constexpr std::size_t maximum_message = 16 * 1024 * 1024;

std::vector<std::uint8_t> point_field(const PublicBytes &point) { return frame(4, point); }

std::optional<PublicBytes> roster_context_digest(const Roster &roster) {
    if (roster.public_keys.empty() || roster.public_keys.size() > 65535)
        return std::nullopt;
    PublicBytes payload;
    std::set<PublicBytes> unique_keys;
    for (const auto &key : roster.public_keys) {
        if (!valid_public_point(key, false) || !unique_keys.insert(key).second)
            return std::nullopt;
        const auto encoded = point_field(key);
        payload.insert(payload.end(), encoded.begin(), encoded.end());
    }
    const auto input =
        transcript("ROSTER", {frame_integer(roster.public_keys.size()), frame(6, payload)});
    std::array<std::uint8_t, 32> digest{};
    std::size_t length = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, input.data(), input.size(), digest.data(),
                     &length) != 1 ||
        length != digest.size() || !std::equal(digest.begin(), digest.end(), roster.digest.begin()))
        return std::nullopt;
    return PublicBytes(digest.begin(), digest.end());
}

PublicBytes make_context(const PublicBytes &sid, const PublicBytes &digest, std::uint32_t threshold,
                         const PublicBytes &message, const PublicBytes &masked_key,
                         const std::vector<std::uint64_t> &subset) {
    PublicBytes subset_payload;
    for (const auto index : subset) {
        const auto encoded = frame_integer(index);
        subset_payload.insert(subset_payload.end(), encoded.begin(), encoded.end());
    }
    const auto subset_transcript = transcript("SUBSET", {frame(6, subset_payload)});
    return transcript("CTX",
                      {frame(2, sid), frame(2, digest), frame_integer(threshold), frame(2, message),
                       point_field(masked_key), frame(2, subset_transcript)});
}
} // namespace

Signer::Signer(std::uint64_t index, SecretScalar secret_key, std::size_t max_used_sessions,
               std::chrono::milliseconds session_timeout)
    : index_(index), secret_key_(std::move(secret_key)), max_used_sessions_(max_used_sessions),
      session_timeout_(session_timeout) {
    if (index_ == 0 || !secret_key_.valid())
        throw std::invalid_argument("invalid signer key");
    if (max_used_sessions_ == 0 || max_used_sessions_ > maximum_remembered_sessions)
        throw std::invalid_argument("invalid signer replay capacity");
    if (session_timeout_ < std::chrono::milliseconds::zero() ||
        session_timeout_ > std::chrono::hours(24 * 365))
        throw std::invalid_argument("invalid signer session timeout");
    if (session_timeout_ != std::chrono::milliseconds::zero()) {
        timeout_worker_ = std::thread([this] {
            std::unique_lock<std::mutex> lock(mutex_);
            while (!stopping_) {
                if (sessions_.empty()) {
                    timeout_changed_.wait(lock);
                    continue;
                }
                auto earliest = std::min_element(sessions_.begin(), sessions_.end(),
                                                 [](const auto &a, const auto &b) {
                                                     return a.second.expires < b.second.expires;
                                                 });
                const auto deadline = earliest->second.expires;
                timeout_changed_.wait_until(lock, deadline);
                const auto now = std::chrono::steady_clock::now();
                for (auto it = sessions_.begin(); it != sessions_.end();) {
                    if (it->second.expires <= now) {
                        active_session_bytes_ -= it->second.accounted_bytes;
                        it = sessions_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        });
    }
}

Signer::~Signer() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
    }
    timeout_changed_.notify_one();
    if (timeout_worker_.joinable())
        timeout_worker_.join();
}

std::optional<RoundOneCommitments> Signer::round1(const Roster &roster, const PublicBytes &sid,
                                                  std::uint32_t threshold,
                                                  const PublicBytes &message,
                                                  const PublicBytes &masked_key,
                                                  const std::vector<std::uint64_t> &subset) {
    if (sid.empty() || sid.size() > 256 || message.size() > maximum_message ||
        roster.public_keys.empty() || roster.public_keys.size() > 65535 || threshold == 0 ||
        threshold > roster.public_keys.size() || subset.size() < threshold || subset.empty() ||
        !valid_public_point(masked_key, false) || !std::is_sorted(subset.begin(), subset.end()) ||
        std::adjacent_find(subset.begin(), subset.end()) != subset.end() ||
        subset.back() > roster.public_keys.size() || subset.front() == 0 ||
        !std::binary_search(subset.begin(), subset.end(), index_))
        return std::nullopt;

    const auto digest = roster_context_digest(roster);
    if (!digest || index_ > roster.public_keys.size() ||
        secret_generator_multiply(secret_key_) != roster.public_keys[index_ - 1])
        return std::nullopt;

    std::lock_guard<std::mutex> lock(mutex_);
    if (used_sessions_.find(sid) != used_sessions_.end() ||
        used_sessions_.size() >= max_used_sessions_)
        return std::nullopt;
    // Account for stored message/context copies and per-session container overhead.
    constexpr std::size_t session_overhead_budget = 4096;
    const std::size_t accounted_bytes = session_overhead_budget + 2 * message.size();
    if (accounted_bytes > maximum_active_session_bytes - active_session_bytes_)
        return std::nullopt;
    used_sessions_.insert(sid);
    try {
        auto first_nonce = random_secret_scalar();
        auto second_nonce = random_secret_scalar();
        RoundOneCommitments commitments{secret_generator_multiply(first_nonce),
                                        secret_generator_multiply(second_nonce)};
        auto context = make_context(sid, *digest, threshold, message, masked_key, subset);
        sessions_.emplace(sid, Session{std::move(first_nonce), std::move(second_nonce),
                                       std::move(context), *digest, masked_key, message, threshold,
                                       session_timeout_ == std::chrono::milliseconds::zero()
                                           ? std::chrono::steady_clock::time_point::max()
                                           : std::chrono::steady_clock::now() + session_timeout_,
                                       accounted_bytes});
        active_session_bytes_ += accounted_bytes;
        timeout_changed_.notify_one();
        return commitments;
    } catch (...) {
        return std::nullopt;
    }
}

bool Signer::cancel(const PublicBytes &sid) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = sessions_.find(sid);
    if (it == sessions_.end())
        return false;
    active_session_bytes_ -= it->second.accounted_bytes;
    sessions_.erase(it);
    return true;
}

std::optional<PublicBytes> Signer::round2(const PublicBytes &sid,
                                          const PublicBytes &aggregate_first,
                                          const PublicBytes &aggregate_second) {
    if (sid.empty() || sid.size() > 256)
        return std::nullopt;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end())
        return std::nullopt;
    if (std::chrono::steady_clock::now() >= it->second.expires) {
        active_session_bytes_ -= it->second.accounted_bytes;
        sessions_.erase(it);
        return std::nullopt;
    }
    auto session = std::move(it->second);
    active_session_bytes_ -= session.accounted_bytes;
    sessions_.erase(it);

    if (!valid_public_point(aggregate_first, false) || !valid_public_point(aggregate_second, false))
        return std::nullopt;
    try {
        const auto beta_transcript =
            transcript("NON", {frame(2, session.context), point_field(aggregate_first),
                               point_field(aggregate_second)});
        const auto beta_array = scalar_challenge(beta_transcript, false);
        const PublicBytes beta(beta_array.begin(), beta_array.end());
        const auto beta_scalar = SecretScalar::from_canonical(beta_array);
        auto weighted_nonce = secret_scalar_multiply(beta_scalar, session.second_nonce);
        auto nonce = secret_scalar_add(session.first_nonce, weighted_nonce);

        const auto weighted_point = public_point_multiply(aggregate_second, beta);
        if (!weighted_point)
            return std::nullopt;
        const auto nonce_point = public_point_add(aggregate_first, *weighted_point);
        if (!nonce_point || !valid_public_point(*nonce_point, false))
            return std::nullopt;
        const std::vector<PublicBytes> challenge_fields{
            frame(2, session.roster_digest), point_field(session.masked_key),
            frame_integer(session.threshold), point_field(*nonce_point), frame(2, session.message)};
        const auto challenge_transcript = transcript("SIG", challenge_fields);
        const auto challenge = scalar_challenge(challenge_transcript, false);
        const auto challenge_scalar = SecretScalar::from_canonical(challenge);
        auto key_product = secret_scalar_multiply(challenge_scalar, secret_key_);
        auto response = secret_scalar_add(nonce, key_product);
        return PublicBytes(response.bytes().begin(), response.bytes().end());
    } catch (...) {
        return std::nullopt;
    }
}
} // namespace hta
