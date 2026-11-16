#include "hta/authorization.hpp"
#include "hta/framing.hpp"
#include "hta/generator_derivation.hpp"
#include "hta/parameters.hpp"
#include "hta/registration.hpp"
#include "hta/scalar_challenge.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
using namespace hta;

SecretScalar secret(std::uint8_t value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.back() = value;
    return SecretScalar::from_canonical(bytes);
}

PublicBytes scalar(std::uint64_t value) {
    PublicBytes result(32, 0);
    for (std::size_t i = 0; i < 8; ++i) {
        result[31 - i] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
    return result;
}

PublicBytes add(const PublicBytes &a, const PublicBytes &b) {
    auto result = public_scalar_add(a, b);
    if (!result)
        throw std::runtime_error("scalar addition failed");
    return *result;
}

PublicBytes subtract(const PublicBytes &a, const PublicBytes &b) {
    auto result = public_scalar_subtract(a, b);
    if (!result)
        throw std::runtime_error("scalar subtraction failed");
    return *result;
}

PublicBytes multiply(const PublicBytes &a, const PublicBytes &b) {
    auto result = public_scalar_multiply(a, b);
    if (!result)
        throw std::runtime_error("scalar multiplication failed");
    return *result;
}

PublicBytes inverse(const PublicBytes &value) {
    // q-2 for secp256k1, evaluated with public field operations.
    static constexpr std::array<std::uint8_t, 32> exponent{
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x3f};
    auto result = scalar(1);
    for (const auto byte : exponent)
        for (int bit = 7; bit >= 0; --bit) {
            result = multiply(result, result);
            if ((byte >> bit) & 1U)
                result = multiply(result, value);
        }
    return result;
}

PublicBytes point_sum(const std::vector<PublicBytes> &points,
                      const std::vector<PublicBytes> &coefficients) {
    auto result = public_msm(points, coefficients);
    if (!result)
        throw std::runtime_error("MSM failed");
    return *result;
}

PublicBytes challenge(const std::string &label,
                      const std::vector<PublicBytes> &fields) {
    const auto bytes = scalar_challenge(transcript(label, fields), true);
    return {bytes.begin(), bytes.end()};
}

PublicBytes derive(const PublicBytes &context, std::uint32_t N, std::uint32_t index) {
    return derive_generator_secp256k1(context, N, index);
}

bool equation_matches_paper(const Roster &roster, const PublicBytes &context,
                            std::uint32_t threshold, const PublicBytes &message,
                            const PublicBytes &key, const AuthorizationProof &proof,
                            bool add_erroneous_minus_z_g) {
    const auto dims = dimensions(static_cast<std::uint32_t>(roster.public_keys.size()), threshold);
    if (!dims)
        return false;
    const auto N = dims->N;
    const auto zero = scalar(0), one = scalar(1);
    const auto H0 = derive(context, N, 1);
    const auto Gxi = derive(context, N, 2 * N + 2);
    const auto Gip = derive(context, N, 2 * N + 3);
    const auto Gbase = *public_generator_multiply(one);

    const auto cfg = transcript("CONFIG", {frame(2, context), frame_integer(N),
                                             frame_integer(proof.r)});
    const PublicBytes roster_digest(roster.digest.begin(), roster.digest.end());
    const auto st = transcript("ST", {frame(2, cfg), frame(2, roster_digest),
                                       frame_integer(roster.public_keys.size()),
                                       frame_integer(threshold), frame(2, message), frame(4, key)});
    const auto T0 = transcript("T0", {frame(2, st), frame(4, proof.A), frame(4, proof.S),
                                       frame(4, proof.Qs)});
    const auto y = challenge("Y", {frame(2, T0)});
    const auto z = challenge("Z", {frame(2, T0), frame(5, y)});
    const auto x = challenge("X", {frame(2, T0), frame(5, y), frame(5, z),
                                     frame(4, proof.T1), frame(4, proof.T2)});

    std::vector<PublicBytes> ypow(N, one), yinvpow(N, one);
    const auto yinv = inverse(y);
    for (std::size_t i = 1; i < N; ++i) {
        ypow[i] = multiply(ypow[i - 1], y);
        yinvpow[i] = multiply(yinvpow[i - 1], yinv);
    }
    const auto z2 = multiply(z, z);
    std::vector<PublicBytes> weights(N, zero);
    for (std::size_t i = 0; i < roster.public_keys.size(); ++i)
        weights[i] = one;
    for (std::uint32_t j = 0; j < dims->ell; ++j) {
        PublicBytes power(32, 0);
        power[31 - j / 8] = static_cast<std::uint8_t>(1U << (j % 8));
        weights[roster.public_keys.size() + j] = subtract(zero, power);
    }

    const auto tp = transcript("TPSI", {frame(2, T0), frame(5, y), frame(5, z),
        frame(4, proof.T1), frame(4, proof.T2), frame(5, x), frame(5, proof.t_hat),
        frame(5, proof.mu), frame(5, proof.mu_xi), frame(5, proof.tau_x)});
    const auto psi = challenge("PSI", {frame(2, tp), frame_integer(0)});
    const auto omega = challenge("PSI", {frame(2, tp), frame_integer(1)});
    const auto tau = transcript("FOLDCTX", {frame(2, tp), frame(5, psi), frame(5, omega)});

    // V1 from Appendix E: t_hat*G + tau_x*H0 = theta*G + x*T1 + x^2*T2.
    PublicBytes sum_y = zero, sum_w = zero;
    for (std::size_t i = 0; i < N; ++i) {
        sum_y = add(sum_y, ypow[i]);
        sum_w = add(sum_w, weights[i]);
    }
    const auto theta = subtract(add(multiply(z2, scalar(threshold)),
                                      multiply(subtract(z, z2), sum_y)),
                                  multiply(multiply(z2, z), sum_w));
    if (point_sum({Gbase, H0, proof.T1, proof.T2},
                  {subtract(proof.t_hat, theta), proof.tau_x, subtract(zero, x),
                   subtract(zero, multiply(x, x))}) != PublicBytes{0})
        return false;

    // P-tilde expanded directly from (5.11), before folding corrections.
    std::vector<PublicBytes> p_points{proof.A, proof.S, H0, Gxi, key, proof.Qs,
                                     Gbase, Gip};
    std::vector<PublicBytes> p_scalars{one, x, subtract(zero, proof.mu),
        subtract(zero, proof.mu_xi), psi, multiply(psi, x),
        subtract(zero, multiply(psi, proof.mu_xi)), multiply(omega, proof.t_hat)};
    std::vector<PublicBytes> G, H, padded_keys;
    G.reserve(N); H.reserve(N); padded_keys = roster.public_keys;
    padded_keys.resize(N, PublicBytes{0});
    for (std::size_t i = 0; i < N; ++i) {
        const auto Gi = derive(context, N, static_cast<std::uint32_t>(i + 2));
        const auto Hi = derive(context, N, static_cast<std::uint32_t>(N + i + 2));
        G.push_back(Gi);
        H.push_back(Hi);
        p_points.push_back(Gi);
        p_scalars.push_back(subtract(zero, z));
        p_points.push_back(Hi);
        p_scalars.push_back(multiply(yinvpow[i], add(multiply(z, ypow[i]),
                                                     multiply(z2, weights[i]))));
        if (i < roster.public_keys.size()) {
            p_points.push_back(roster.public_keys[i]);
            p_scalars.push_back(subtract(zero, multiply(psi, z)));
        }
    }
    if (add_erroneous_minus_z_g) {
        p_points.push_back(Gbase);
        p_scalars.push_back(subtract(zero, z));
    }
    auto lhs = point_sum(p_points, p_scalars);

    // Fold the public generators exactly as Algorithm 3 specifies.
    for (std::size_t i = 0; i < N; ++i) {
        G[i] = point_sum({G[i], padded_keys[i]}, {one, psi});
        H[i] = *public_point_multiply(H[i], yinvpow[i]);
    }
    const auto U = *public_point_multiply(Gip, omega);
    std::vector<PublicBytes> us;
    for (std::uint32_t j = 0; j < proof.r; ++j) {
        PublicBytes old_challenges, old_points;
        for (const auto &u : us) {
            const auto f = frame(5, u);
            old_challenges.insert(old_challenges.end(), f.begin(), f.end());
        }
        for (std::size_t k = 0; k <= j; ++k)
            for (const auto *point : {&proof.L[k], &proof.R[k]}) {
                const auto f = frame(4, *point);
                old_points.insert(old_points.end(), f.begin(), f.end());
            }
        const auto u = challenge("UPSILON", {frame_integer(j + 1), frame(2, tau),
            frame(6, old_challenges), frame(6, old_points)});
        const auto ui = inverse(u);
        us.push_back(u);
        const auto m = G.size() / 2;
        std::vector<PublicBytes> next_G, next_H;
        for (std::size_t i = 0; i < m; ++i) {
            next_G.push_back(point_sum({G[i], G[i + m]}, {ui, u}));
            next_H.push_back(point_sum({H[i], H[i + m]}, {u, ui}));
        }
        G = std::move(next_G);
        H = std::move(next_H);
        lhs = point_sum({lhs, proof.L[j], proof.R[j]}, {one, multiply(u, u), multiply(ui, ui)});
    }

    PublicBytes inner = zero;
    for (std::size_t i = 0; i < proof.vL.size(); ++i)
        inner = add(inner, multiply(proof.vL[i], proof.vR[i]));
    std::vector<PublicBytes> rhs_points = G;
    rhs_points.insert(rhs_points.end(), H.begin(), H.end());
    rhs_points.push_back(U);
    std::vector<PublicBytes> rhs_scalars = proof.vL;
    rhs_scalars.insert(rhs_scalars.end(), proof.vR.begin(), proof.vR.end());
    rhs_scalars.push_back(inner);
    const auto rhs = point_sum(rhs_points, rhs_scalars);
    return lhs == rhs;
}
} // namespace

int main() {
    try {
        const PublicBytes registry{'e','q'}, context{'e','q','-','g'}, message{'m'};
        const auto r1 = create_registration(secret(7), 1, registry);
        const auto r2 = create_registration(secret(11), 2, registry);
        const auto r3 = create_registration(secret(19), 3, registry);
        const auto roster = build_roster({r1, r2, r3}, registry);
        if (!roster)
            return 1;
        auto sum = public_point_add(roster->public_keys[0], roster->public_keys[1]);
        auto key = sum ? public_point_add(*sum, secret_generator_multiply(secret(13))) : std::nullopt;
        if (!key)
            return 2;
        const auto dims = dimensions(3, 2);
        if (!dims)
            return 3;
        for (std::uint32_t r = 0; r <= dims->kappa; ++r) {
            auto proof = prove_authorization(*roster, context, 2, message, *key,
                                             {1,1,0}, {0,0}, secret(13), r);
            if (!proof || !verify_authorization(*roster, context, 2, message, *key, *proof, r))
                return 4;
            if (!equation_matches_paper(*roster, context, 2, message, *key, *proof, false)) {
                std::cerr << "paper V1/V2 equation mismatch at r=" << r << '\n';
                return 5;
            }
            // This is the historical regression: a second standalone -zG makes
            // the paper's V2 equality false for a valid certificate.
            if (equation_matches_paper(*roster, context, 2, message, *key, *proof, true)) {
                std::cerr << "erroneous extra -zG unexpectedly satisfies V2 at r=" << r << '\n';
                return 6;
            }
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 7;
    }
    return 0;
}
