#include "hta/coordinator.hpp"

#include "hta/framing.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace hta {
namespace {
constexpr std::size_t maximum_message = 16 * 1024 * 1024;

PublicBytes point_field(const PublicBytes &point) { return frame(4, point); }

std::optional<PublicBytes> checked_roster_digest(const Roster &roster) {
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

std::optional<PublicBytes> add(const PublicBytes &left, const PublicBytes &right) {
    return public_point_add(left, right);
}
} // namespace

CoordinatorSession::CoordinatorSession(PublicBytes digest, std::vector<PublicBytes> roster_keys,
                                       std::uint32_t threshold, PublicBytes message,
                                       std::vector<std::uint64_t> subset, PublicBytes masked_key,
                                       SecretScalar tweak, PublicBytes context)
    : digest_(std::move(digest)), roster_keys_(std::move(roster_keys)), threshold_(threshold),
      message_(std::move(message)), subset_(std::move(subset)), masked_key_(std::move(masked_key)),
      tweak_(std::move(tweak)), context_(std::move(context)) {}

void CoordinatorSession::close() noexcept {
    state_ = State::closed;
    SecretScalar consumed(std::move(tweak_));
    OPENSSL_cleanse(challenge_.data(), challenge_.size());
}

std::optional<CoordinatorSession>
CoordinatorSession::begin(const Roster &roster, const PublicBytes &sid, std::uint32_t threshold,
                          const PublicBytes &message, std::vector<std::uint64_t> subset,
                          SecretScalar tweak) {
    if (!tweak.valid() || sid.empty() || sid.size() > 256 || message.size() > maximum_message ||
        roster.public_keys.empty() || roster.public_keys.size() > 65535 || threshold == 0 ||
        threshold > roster.public_keys.size() || subset.empty() || subset.size() < threshold ||
        !std::is_sorted(subset.begin(), subset.end()) ||
        std::adjacent_find(subset.begin(), subset.end()) != subset.end() || subset.front() == 0 ||
        subset.back() > roster.public_keys.size())
        return std::nullopt;
    const auto digest = checked_roster_digest(roster);
    if (!digest)
        return std::nullopt;

    PublicBytes selected_key{0};
    for (const auto index : subset) {
        const auto sum = add(selected_key, roster.public_keys[index - 1]);
        if (!sum)
            return std::nullopt;
        selected_key = *sum;
    }
    const auto tweak_point = secret_generator_multiply(tweak);
    const auto masked_key = add(selected_key, tweak_point);
    if (!masked_key || !valid_public_point(*masked_key, false))
        return std::nullopt;
    auto context = make_context(sid, *digest, threshold, message, *masked_key, subset);
    return CoordinatorSession(*digest, roster.public_keys, threshold, message, std::move(subset),
                              *masked_key, std::move(tweak), std::move(context));
}

std::optional<AggregateCommitments> CoordinatorSession::collect_commitments(
    const std::map<std::uint64_t, RoundOneCommitments> &commitments) {
    if (state_ != State::collecting_commitments || commitments.size() != subset_.size()) {
        close();
        return std::nullopt;
    }
    PublicBytes first{0};
    PublicBytes second{0};
    for (const auto index : subset_) {
        const auto found = commitments.find(index);
        if (found == commitments.end() || !valid_public_point(found->second.first, false) ||
            !valid_public_point(found->second.second, false)) {
            close();
            return std::nullopt;
        }
        const auto sum_first = add(first, found->second.first);
        const auto sum_second = add(second, found->second.second);
        if (!sum_first || !sum_second) {
            close();
            return std::nullopt;
        }
        first = *sum_first;
        second = *sum_second;
    }
    if (!valid_public_point(first, false) || !valid_public_point(second, false)) {
        close();
        return std::nullopt;
    }

    const auto beta_input =
        transcript("NON", {frame(2, context_), point_field(first), point_field(second)});
    const auto beta = scalar_challenge(beta_input, false);
    const PublicBytes beta_bytes(beta.begin(), beta.end());
    const auto weighted = public_point_multiply(second, beta_bytes);
    const auto nonce = weighted ? add(first, *weighted) : std::nullopt;
    if (!nonce || !valid_public_point(*nonce, false)) {
        close();
        return std::nullopt;
    }
    const auto signature_input =
        transcript("SIG", {frame(2, digest_), point_field(masked_key_), frame_integer(threshold_),
                           point_field(*nonce), frame(2, message_)});
    challenge_ = scalar_challenge(signature_input, false);
    nonce_challenge_ = beta_bytes;
    nonce_ = *nonce;
    commitments_ = commitments;
    state_ = State::collecting_responses;
    return AggregateCommitments{std::move(first), std::move(second)};
}

bool CoordinatorSession::verify_partial_response(std::uint64_t index,
                                                 const PublicBytes &response) const {
    if (state_ != State::collecting_responses ||
        !std::binary_search(subset_.begin(), subset_.end(), index) || index == 0 ||
        index > roster_keys_.size() || !valid_public_scalar(response))
        return false;
    const auto found = commitments_.find(index);
    if (found == commitments_.end() || !valid_public_point(found->second.first, false) ||
        !valid_public_point(found->second.second, false))
        return false;
    const auto weighted_nonce = public_point_multiply(found->second.second, nonce_challenge_);
    const auto nonce = weighted_nonce ? add(found->second.first, *weighted_nonce) : std::nullopt;
    const PublicBytes signature_challenge(challenge_.begin(), challenge_.end());
    const auto weighted_key = public_point_multiply(roster_keys_[index - 1], signature_challenge);
    const auto right = nonce && weighted_key ? add(*nonce, *weighted_key) : std::nullopt;
    const auto left = public_generator_multiply(response);
    return left && right && *left == *right;
}

std::optional<SchnorrSignature>
CoordinatorSession::aggregate_responses(const std::map<std::uint64_t, PublicBytes> &responses) {
    if (state_ != State::collecting_responses || responses.size() != subset_.size()) {
        close();
        return std::nullopt;
    }
    SecretScalar tweak(std::move(tweak_));
    state_ = State::closed;
    PublicBytes aggregate(32, 0);
    for (const auto index : subset_) {
        const auto found = responses.find(index);
        if (found == responses.end() || !valid_public_scalar(found->second)) {
            OPENSSL_cleanse(challenge_.data(), challenge_.size());
            return std::nullopt;
        }
        const auto sum = public_scalar_add(aggregate, found->second);
        if (!sum) {
            OPENSSL_cleanse(challenge_.data(), challenge_.size());
            return std::nullopt;
        }
        aggregate = *sum;
    }
    try {
        auto challenge_scalar = SecretScalar::from_canonical(challenge_);
        auto tweak_response = secret_scalar_multiply(challenge_scalar, tweak);
        const auto final_response = public_scalar_add(
            aggregate, PublicBytes(tweak_response.bytes().begin(), tweak_response.bytes().end()));
        if (!final_response) {
            OPENSSL_cleanse(challenge_.data(), challenge_.size());
            return std::nullopt;
        }
        const auto left = public_generator_multiply(*final_response);
        const PublicBytes challenge_bytes(challenge_.begin(), challenge_.end());
        const auto challenge_key = public_point_multiply(masked_key_, challenge_bytes);
        const auto right = challenge_key ? add(nonce_, *challenge_key) : std::nullopt;
        OPENSSL_cleanse(challenge_.data(), challenge_.size());
        if (!left || !right || *left != *right)
            return std::nullopt;
        return SchnorrSignature{masked_key_, nonce_, *final_response};
    } catch (...) {
        OPENSSL_cleanse(challenge_.data(), challenge_.size());
        return std::nullopt;
    }
}
} // namespace hta
