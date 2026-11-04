#include "hta/authorization.hpp"
#include "authorization_test.hpp"

#include "hta/framing.hpp"
#include "hta/generator_derivation.hpp"
#include "hta/parameters.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace hta {
namespace {
constexpr std::size_t maximum_message = 16 * 1024 * 1024;
const PublicBytes base_point{2,    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
                             0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
                             0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};

struct Parameters {
    PublicBytes digest;
    Dimensions dims;
};

struct Generators {
    PublicBytes H0;
    std::vector<PublicBytes> G;
    std::vector<PublicBytes> H;
};

std::optional<Parameters> validate_public(const Roster &roster, const PublicBytes &context,
                                          std::uint32_t threshold, const PublicBytes &message,
                                          const PublicBytes &masked_key) {
    if (roster.public_keys.empty() || roster.public_keys.size() > 65535 ||
        context.size() > 1024 * 1024 || message.size() > maximum_message ||
        !valid_public_point(masked_key, false))
        return std::nullopt;
    const auto dims = dimensions(static_cast<std::uint32_t>(roster.public_keys.size()), threshold);
    if (!dims)
        return std::nullopt;
    PublicBytes payload;
    std::set<PublicBytes> unique;
    for (const auto &key : roster.public_keys) {
        if (!valid_public_point(key, false) || !unique.insert(key).second)
            return std::nullopt;
        const auto framed = frame(4, key);
        payload.insert(payload.end(), framed.begin(), framed.end());
    }
    const auto input =
        transcript("ROSTER", {frame_integer(roster.public_keys.size()), frame(6, payload)});
    std::array<std::uint8_t, 32> digest{};
    std::size_t digest_size = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, input.data(), input.size(), digest.data(),
                     &digest_size) != 1 ||
        digest_size != digest.size() ||
        !std::equal(digest.begin(), digest.end(), roster.digest.begin()))
        return std::nullopt;
    return Parameters{PublicBytes(digest.begin(), digest.end()), *dims};
}

Generators derive_generators(const PublicBytes &context, std::uint32_t N) {
    Generators result;
    result.H0 = derive_generator_secp256k1(context, N, 1);
    result.G.reserve(N);
    result.H.reserve(N);
    for (std::uint32_t i = 0; i < N; ++i)
        result.G.push_back(derive_generator_secp256k1(context, N, i + 2));
    for (std::uint32_t i = 0; i < N; ++i)
        result.H.push_back(derive_generator_secp256k1(context, N, N + i + 2));
    return result;
}

SecretScalar scalar_value(std::uint64_t value) {
    std::array<std::uint8_t, 32> encoded{};
    for (std::size_t i = 0; i < 8; ++i) {
        encoded[31 - i] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
    return SecretScalar::from_canonical(encoded);
}

SecretScalar zero_scalar() { return scalar_value(0); }
SecretScalar one_scalar() { return scalar_value(1); }

SecretScalar clone(const SecretScalar &value) {
    auto encoded = value.bytes();
    auto result = SecretScalar::from_canonical(encoded);
    OPENSSL_cleanse(encoded.data(), encoded.size());
    return result;
}

PublicBytes public_bytes(const SecretScalar &value) {
    return {value.bytes().begin(), value.bytes().end()};
}

std::vector<SecretScalar> clone_vector(const std::vector<SecretScalar> &values) {
    std::vector<SecretScalar> result;
    result.reserve(values.size());
    for (const auto &value : values)
        result.push_back(clone(value));
    return result;
}

SecretScalar secret_inner_product(const std::vector<SecretScalar> &left,
                                  const std::vector<SecretScalar> &right) {
    auto sum = zero_scalar();
    for (std::size_t i = 0; i < left.size(); ++i) {
        auto product = secret_scalar_multiply(left[i], right[i]);
        sum = secret_scalar_add(sum, product);
    }
    return sum;
}

PublicBytes statement(const PublicBytes &digest, std::uint32_t n, std::uint32_t threshold,
                      const PublicBytes &message, const PublicBytes &masked_key) {
    return transcript("ST", {frame(2, digest), frame_integer(n), frame_integer(threshold),
                             frame(2, message), frame(4, masked_key)});
}

PublicBytes proof_prefix(const PublicBytes &st, const AuthorizationProof &proof) {
    return transcript("T0",
                      {frame(2, st), frame(4, proof.A), frame(4, proof.S), frame(4, proof.Qs)});
}

std::vector<PublicBytes> powers(const PublicBytes &y, std::size_t N) {
    std::vector<PublicBytes> result;
    result.reserve(N);
    PublicBytes current(32, 0);
    current.back() = 1;
    for (std::size_t i = 0; i < N; ++i) {
        result.push_back(current);
        const auto next = public_scalar_multiply(current, y);
        if (!next)
            throw std::runtime_error("invalid public scalar power");
        current = *next;
    }
    return result;
}

std::pair<std::vector<PublicBytes>, std::vector<PublicBytes>> public_chi_w(std::size_t n,
                                                                           const Dimensions &dims) {
    std::vector<PublicBytes> chi(dims.N, PublicBytes(32, 0));
    std::vector<PublicBytes> w(dims.N, PublicBytes(32, 0));
    PublicBytes one(32, 0);
    one.back() = 1;
    for (std::size_t i = 0; i < n + dims.ell; ++i)
        chi[i] = one;
    for (std::size_t i = 0; i < n; ++i)
        w[i] = one;
    for (std::uint32_t j = 0; j < dims.ell; ++j) {
        PublicBytes power(32, 0);
        power.back() = static_cast<std::uint8_t>(std::uint64_t{1} << j);
        const auto negative = public_scalar_subtract(PublicBytes(32, 0), power);
        if (!negative)
            throw std::runtime_error("invalid public surplus weight");
        w[n + j] = *negative;
    }
    return {std::move(chi), std::move(w)};
}

PublicBytes must(std::optional<PublicBytes> value) {
    if (!value)
        throw std::runtime_error("invalid public field or group operation");
    return std::move(*value);
}

PublicBytes public_inner_product(const std::vector<PublicBytes> &left,
                                 const std::vector<PublicBytes> &right) {
    PublicBytes sum(32, 0);
    for (std::size_t i = 0; i < left.size(); ++i)
        sum = must(public_scalar_add(sum, must(public_scalar_multiply(left[i], right[i]))));
    return sum;
}

PublicBytes public_challenge(const PublicBytes &input, bool nonzero) {
    const auto value = scalar_challenge(input, nonzero);
    return {value.begin(), value.end()};
}

bool bit_vector(const std::vector<std::uint8_t> &bits) {
    return std::all_of(bits.begin(), bits.end(), [](std::uint8_t bit) { return bit <= 1; });
}

} // namespace

std::optional<AuthorizationProof>
prove_authorization(const Roster &roster, const PublicBytes &generator_context,
                    std::uint32_t threshold, const PublicBytes &message,
                    const PublicBytes &masked_key, const std::vector<std::uint8_t> &selectors,
                    const std::vector<std::uint8_t> &surplus_bits,
                    // Move-only ownership transfer keeps secret cleanup local to this call.
                    // cppcheck-suppress passedByValue
                    SecretScalar tweak) {
    const auto params = validate_public(roster, generator_context, threshold, message, masked_key);
    if (!params || !tweak.valid() || selectors.size() != roster.public_keys.size() ||
        surplus_bits.size() != params->dims.ell || !bit_vector(selectors) ||
        !bit_vector(surplus_bits))
        return std::nullopt;

    std::uint64_t selected_count = 0;
    for (const auto bit : selectors)
        selected_count += bit;
    std::uint64_t surplus = 0;
    for (std::size_t j = 0; j < surplus_bits.size(); ++j)
        surplus += std::uint64_t{surplus_bits[j]} << j;
    if (selected_count < threshold || selected_count - threshold != surplus)
        return std::nullopt;

    try {
        auto gens = derive_generators(generator_context, params->dims.N);
        std::vector<SecretScalar> aL, aR;
        aL.reserve(params->dims.N);
        aR.reserve(params->dims.N);
        auto one = one_scalar();
        std::vector<SecretScalar> selected_scalars;
        selected_scalars.reserve(selectors.size());
        for (const auto bit : selectors) {
            selected_scalars.push_back(scalar_value(bit));
            auto value = scalar_value(bit);
            aL.push_back(clone(value));
            aR.push_back(secret_scalar_subtract(value, one));
        }
        for (const auto bit : surplus_bits) {
            auto value = scalar_value(bit);
            aL.push_back(clone(value));
            aR.push_back(secret_scalar_subtract(value, one));
        }
        aL.push_back(clone(tweak));
        aR.push_back(zero_scalar());

        const auto selected_public = secret_msm(roster.public_keys, selected_scalars);
        const auto tweak_public = secret_generator_multiply(tweak);
        const auto linked_key = must(public_point_add(selected_public, tweak_public));
        if (linked_key != masked_key)
            return std::nullopt;

        auto alpha = random_secret_scalar_allow_zero();
        auto rho = random_secret_scalar_allow_zero();
        auto tau1 = random_secret_scalar_allow_zero();
        auto tau2 = random_secret_scalar_allow_zero();
        std::vector<SecretScalar> sL, sR;
        sL.reserve(params->dims.N);
        sR.reserve(params->dims.N);
        for (std::uint32_t i = 0; i < params->dims.N; ++i) {
            sL.push_back(random_secret_scalar_allow_zero());
            sR.push_back(random_secret_scalar_allow_zero());
        }

        std::vector<PublicBytes> a_points{gens.H0};
        a_points.insert(a_points.end(), gens.G.begin(), gens.G.end());
        a_points.insert(a_points.end(), gens.H.begin(), gens.H.end());
        std::vector<SecretScalar> a_scalars;
        a_scalars.reserve(1 + 2 * params->dims.N);
        a_scalars.push_back(clone(alpha));
        auto left_clones = clone_vector(aL);
        auto right_clones = clone_vector(aR);
        for (auto &value : left_clones)
            a_scalars.push_back(std::move(value));
        for (auto &value : right_clones)
            a_scalars.push_back(std::move(value));
        const auto A = secret_msm(a_points, a_scalars);

        std::vector<SecretScalar> s_scalars;
        s_scalars.reserve(1 + 2 * params->dims.N);
        s_scalars.push_back(clone(rho));
        auto s_left_clones = clone_vector(sL);
        auto s_right_clones = clone_vector(sR);
        for (auto &value : s_left_clones)
            s_scalars.push_back(std::move(value));
        for (auto &value : s_right_clones)
            s_scalars.push_back(std::move(value));
        const auto Scom = secret_msm(a_points, s_scalars);

        std::vector<PublicBytes> padded_keys = roster.public_keys;
        padded_keys.insert(padded_keys.end(), params->dims.ell, PublicBytes{0});
        padded_keys.push_back(base_point);
        const auto Qs = secret_msm(padded_keys, sL);
        AuthorizationProof proof;
        proof.A = A;
        proof.S = Scom;
        proof.Qs = Qs;
        const auto st =
            statement(params->digest, static_cast<std::uint32_t>(roster.public_keys.size()),
                      threshold, message, masked_key);
        const auto T0 = proof_prefix(st, proof);
        const auto y = public_challenge(transcript("Y", {frame(2, T0)}), true);
        const auto z = public_challenge(transcript("Z", {frame(2, T0), frame(5, y)}), true);
        const auto y_values = powers(y, params->dims.N);
        auto z_secret = SecretScalar::from_canonical([&] {
            std::array<std::uint8_t, 32> bytes{};
            std::copy(z.begin(), z.end(), bytes.begin());
            return bytes;
        }());
        auto z2 = secret_scalar_multiply(z_secret, z_secret);
        auto chi_w = public_chi_w(roster.public_keys.size(), params->dims);
        std::vector<SecretScalar> l0, r0, r1;
        l0.reserve(params->dims.N);
        r0.reserve(params->dims.N);
        r1.reserve(params->dims.N);
        for (std::uint32_t i = 0; i < params->dims.N; ++i) {
            auto chi_i = SecretScalar::from_canonical([&] {
                std::array<std::uint8_t, 32> bytes{};
                std::copy(chi_w.first[i].begin(), chi_w.first[i].end(), bytes.begin());
                return bytes;
            }());
            auto w_i = SecretScalar::from_canonical([&] {
                std::array<std::uint8_t, 32> bytes{};
                std::copy(chi_w.second[i].begin(), chi_w.second[i].end(), bytes.begin());
                return bytes;
            }());
            auto y_i = SecretScalar::from_canonical([&] {
                std::array<std::uint8_t, 32> bytes{};
                std::copy(y_values[i].begin(), y_values[i].end(), bytes.begin());
                return bytes;
            }());
            auto zchi = secret_scalar_multiply(z_secret, chi_i);
            l0.push_back(secret_scalar_subtract(aL[i], zchi));
            auto right_base = secret_scalar_add(aR[i], zchi);
            auto right_scaled = secret_scalar_multiply(y_i, right_base);
            auto right_weight = secret_scalar_multiply(z2, w_i);
            r0.push_back(secret_scalar_add(right_scaled, right_weight));
            r1.push_back(secret_scalar_multiply(y_i, sR[i]));
        }
        auto t1 = secret_scalar_add(secret_inner_product(l0, r1), secret_inner_product(sL, r0));
        auto t2 = secret_inner_product(sL, r1);
        std::vector<SecretScalar> t1_scalars;
        t1_scalars.push_back(clone(t1));
        t1_scalars.push_back(clone(tau1));
        const auto T1 = secret_msm({base_point, gens.H0}, t1_scalars);
        std::vector<SecretScalar> t2_scalars;
        t2_scalars.push_back(clone(t2));
        t2_scalars.push_back(clone(tau2));
        const auto T2 = secret_msm({base_point, gens.H0}, t2_scalars);
        proof.T1 = T1;
        proof.T2 = T2;
        const auto x = public_challenge(
            transcript("X", {frame(2, T0), frame(5, y), frame(5, z), frame(4, T1), frame(4, T2)}),
            true);
        auto x_secret = SecretScalar::from_canonical([&] {
            std::array<std::uint8_t, 32> bytes{};
            std::copy(x.begin(), x.end(), bytes.begin());
            return bytes;
        }());
        auto x2_secret = secret_scalar_multiply(x_secret, x_secret);
        std::vector<SecretScalar> vL, vR;
        vL.reserve(params->dims.N);
        vR.reserve(params->dims.N);
        for (std::uint32_t i = 0; i < params->dims.N; ++i) {
            vL.push_back(secret_scalar_add(aL[i], secret_scalar_multiply(x_secret, sL[i])));
            vR.push_back(secret_scalar_add(aR[i], secret_scalar_multiply(x_secret, sR[i])));
        }
        auto mu = secret_scalar_add(alpha, secret_scalar_multiply(x_secret, rho));
        auto tau_x = secret_scalar_add(secret_scalar_multiply(x_secret, tau1),
                                       secret_scalar_multiply(x2_secret, tau2));

        std::vector<SecretScalar> c3_left, c3_right;
        c3_left.reserve(params->dims.N);
        c3_right.reserve(params->dims.N);
        for (std::uint32_t i = 0; i < params->dims.N; ++i) {
            auto chi_i = SecretScalar::from_canonical([&] {
                std::array<std::uint8_t, 32> bytes{};
                std::copy(chi_w.first[i].begin(), chi_w.first[i].end(), bytes.begin());
                return bytes;
            }());
            auto w_i = SecretScalar::from_canonical([&] {
                std::array<std::uint8_t, 32> bytes{};
                std::copy(chi_w.second[i].begin(), chi_w.second[i].end(), bytes.begin());
                return bytes;
            }());
            auto y_i = SecretScalar::from_canonical([&] {
                std::array<std::uint8_t, 32> bytes{};
                std::copy(y_values[i].begin(), y_values[i].end(), bytes.begin());
                return bytes;
            }());
            auto zchi = secret_scalar_multiply(z_secret, chi_i);
            c3_left.push_back(secret_scalar_subtract(vL[i], zchi));
            auto right_base = secret_scalar_add(vR[i], zchi);
            auto right_scaled = secret_scalar_multiply(y_i, right_base);
            auto right_weight = secret_scalar_multiply(z2, w_i);
            c3_right.push_back(secret_scalar_add(right_scaled, right_weight));
        }
        auto t_hat = secret_inner_product(c3_left, c3_right);
        proof.vL.reserve(params->dims.N);
        proof.vR.reserve(params->dims.N);
        for (const auto &value : vL)
            proof.vL.push_back(public_bytes(value));
        for (const auto &value : vR)
            proof.vR.push_back(public_bytes(value));
        proof.t_hat = public_bytes(t_hat);
        proof.mu = public_bytes(mu);
        proof.tau_x = public_bytes(tau_x);
        return proof;
    } catch (...) {
        return std::nullopt;
    }
}

namespace {
template <typename ChallengeProvider>
bool verify_authorization_impl(const Roster &roster, const PublicBytes &generator_context,
                               std::uint32_t threshold, const PublicBytes &message,
                               const PublicBytes &masked_key, const AuthorizationProof &proof,
                               const ChallengeProvider &challenge_provider) {
    const auto params = validate_public(roster, generator_context, threshold, message, masked_key);
    if (!params || !valid_public_point(proof.A, true) || !valid_public_point(proof.S, true) ||
        !valid_public_point(proof.Qs, true) || !valid_public_point(proof.T1, true) ||
        !valid_public_point(proof.T2, true) || proof.vL.size() != params->dims.N ||
        proof.vR.size() != params->dims.N || !valid_public_scalar(proof.t_hat) ||
        !valid_public_scalar(proof.mu) || !valid_public_scalar(proof.tau_x) ||
        !std::all_of(proof.vL.begin(), proof.vL.end(), valid_public_scalar) ||
        !std::all_of(proof.vR.begin(), proof.vR.end(), valid_public_scalar))
        return false;
    try {
        const auto gens = derive_generators(generator_context, params->dims.N);
        auto padded_keys = roster.public_keys;
        padded_keys.insert(padded_keys.end(), params->dims.ell, PublicBytes{0});
        padded_keys.push_back(base_point);
        const auto st =
            statement(params->digest, static_cast<std::uint32_t>(roster.public_keys.size()),
                      threshold, message, masked_key);
        const auto T0 = proof_prefix(st, proof);
        const auto y = challenge_provider(transcript("Y", {frame(2, T0)}), true);
        const auto z = challenge_provider(transcript("Z", {frame(2, T0), frame(5, y)}), true);
        const auto x = challenge_provider(transcript("X", {frame(2, T0), frame(5, y), frame(5, z),
                                                           frame(4, proof.T1), frame(4, proof.T2)}),
                                          true);
        const auto y_values = powers(y, params->dims.N);
        const auto chi_w = public_chi_w(roster.public_keys.size(), params->dims);

        std::vector<PublicBytes> c1_points{gens.H0};
        c1_points.insert(c1_points.end(), gens.G.begin(), gens.G.end());
        c1_points.insert(c1_points.end(), gens.H.begin(), gens.H.end());
        std::vector<PublicBytes> c1_scalars{proof.mu};
        c1_scalars.insert(c1_scalars.end(), proof.vL.begin(), proof.vL.end());
        c1_scalars.insert(c1_scalars.end(), proof.vR.begin(), proof.vR.end());
        const auto left_c1 =
            must(public_point_add(proof.A, must(public_point_multiply(proof.S, x))));
        const auto right_c1 = public_msm(c1_points, c1_scalars);
        if (!right_c1 || left_c1 != *right_c1)
            return false;

        const auto left_c2 =
            must(public_point_add(masked_key, must(public_point_multiply(proof.Qs, x))));
        const auto right_c2 = public_msm(padded_keys, proof.vL);
        if (!right_c2 || left_c2 != *right_c2)
            return false;

        std::vector<PublicBytes> c3_left(params->dims.N), c3_right(params->dims.N);
        for (std::uint32_t i = 0; i < params->dims.N; ++i) {
            const auto zchi = must(public_scalar_multiply(z, chi_w.first[i]));
            c3_left[i] = must(public_scalar_subtract(proof.vL[i], zchi));
            const auto right_base = must(public_scalar_add(proof.vR[i], zchi));
            c3_right[i] = must(public_scalar_add(
                must(public_scalar_multiply(y_values[i], right_base)),
                must(public_scalar_multiply(must(public_scalar_multiply(z, z)), chi_w.second[i]))));
        }
        const auto c3 = public_inner_product(c3_left, c3_right);
        if (c3 != proof.t_hat)
            return false;

        const auto z2 = must(public_scalar_multiply(z, z));
        const auto z3 = must(public_scalar_multiply(z2, z));
        PublicBytes chi_y(32, 0);
        for (std::size_t i = 0; i < roster.public_keys.size() + params->dims.ell; ++i)
            chi_y = must(public_scalar_add(chi_y, y_values[i]));
        PublicBytes chi_w_sum(32, 0);
        for (std::size_t i = 0; i < params->dims.N; ++i)
            chi_w_sum = must(public_scalar_add(
                chi_w_sum, must(public_scalar_multiply(chi_w.first[i], chi_w.second[i]))));
        const auto delta = must(public_scalar_subtract(
            must(public_scalar_multiply(must(public_scalar_subtract(z, z2)), chi_y)),
            must(public_scalar_multiply(z3, chi_w_sum))));
        PublicBytes threshold_scalar(32, 0);
        threshold_scalar[28] = static_cast<std::uint8_t>(threshold >> 24);
        threshold_scalar[29] = static_cast<std::uint8_t>(threshold >> 16);
        threshold_scalar[30] = static_cast<std::uint8_t>(threshold >> 8);
        threshold_scalar[31] = static_cast<std::uint8_t>(threshold);
        const auto theta =
            must(public_scalar_add(must(public_scalar_multiply(z2, threshold_scalar)), delta));
        const auto x2 = must(public_scalar_multiply(x, x));
        const auto left_c4 = public_msm({base_point, gens.H0}, {proof.t_hat, proof.tau_x});
        const auto right_c4 = public_msm({base_point, proof.T1, proof.T2}, {theta, x, x2});
        return left_c4 && right_c4 && *left_c4 == *right_c4;
    } catch (...) {
        return false;
    }
}
} // namespace

bool verify_authorization(const Roster &roster, const PublicBytes &generator_context,
                          std::uint32_t threshold, const PublicBytes &message,
                          const PublicBytes &masked_key, const AuthorizationProof &proof) {
    return verify_authorization_impl(
        roster, generator_context, threshold, message, masked_key, proof,
        [](const PublicBytes &input, bool nonzero) { return public_challenge(input, nonzero); });
}

bool testing::verify_authorization_with_challenges(
    const Roster &roster, const PublicBytes &generator_context, std::uint32_t threshold,
    const PublicBytes &message, const PublicBytes &masked_key, const AuthorizationProof &proof,
    const ChallengeProvider &challenge) {
    if (!challenge)
        return false;
    try {
        return verify_authorization_impl(roster, generator_context, threshold, message, masked_key,
                                         proof, challenge);
    } catch (...) {
        return false;
    }
}

bool verify_signature(const Roster &roster, const PublicBytes &generator_context,
                      std::uint32_t threshold, const PublicBytes &message,
                      const FinalSignature &signature) {
    const auto &schnorr = signature.schnorr;
    if (!valid_public_point(schnorr.masked_key, false) ||
        !valid_public_point(schnorr.nonce, false) || !valid_public_scalar(schnorr.response))
        return false;
    try {
        const auto digest =
            validate_public(roster, generator_context, threshold, message, schnorr.masked_key);
        if (!digest)
            return false;
        const auto challenge_input = transcript(
            "SIG", {frame(2, digest->digest), frame(4, schnorr.masked_key),
                    frame_integer(threshold), frame(4, schnorr.nonce), frame(2, message)});
        const auto challenge = public_challenge(challenge_input, false);
        const auto left = public_generator_multiply(schnorr.response);
        const auto weighted_key = public_point_multiply(schnorr.masked_key, challenge);
        const auto right =
            weighted_key ? public_point_add(schnorr.nonce, *weighted_key) : std::nullopt;
        return left && right && *left == *right &&
               verify_authorization(roster, generator_context, threshold, message,
                                    schnorr.masked_key, signature.authorization);
    } catch (...) {
        return false;
    }
}
} // namespace hta
