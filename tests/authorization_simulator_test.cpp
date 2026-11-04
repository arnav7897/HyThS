#include "authorization_test.hpp"

#include "hta/framing.hpp"
#include "hta/generator_derivation.hpp"
#include "hta/parameters.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"
#include "hta/secret_scalar.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <map>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using hta::AuthorizationProof;
using hta::PublicBytes;
using ChallengeMap = std::map<PublicBytes, PublicBytes>;

PublicBytes scalar(std::uint8_t value) {
    PublicBytes out(32, 0);
    out.back() = value;
    return out;
}

PublicBytes negative_one() {
    return {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
            0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40};
}

PublicBytes require(std::optional<PublicBytes> value) {
    if (!value)
        throw std::runtime_error("public operation failed");
    return *value;
}

PublicBytes inverse(const PublicBytes &value) {
    static constexpr char order_hex[] =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    BIGNUM *number = BN_bin2bn(value.data(), static_cast<int>(value.size()), nullptr);
    BIGNUM *order = nullptr;
    BIGNUM *result = BN_new();
    BN_CTX *context = BN_CTX_new();
    if (!number || !result || !context || BN_hex2bn(&order, order_hex) == 0 ||
        !BN_mod_inverse(result, number, order, context)) {
        BN_free(number);
        BN_free(order);
        BN_free(result);
        BN_CTX_free(context);
        throw std::runtime_error("scalar inversion failed");
    }
    PublicBytes out(32);
    BN_bn2binpad(result, out.data(), static_cast<int>(out.size()));
    BN_free(number);
    BN_free(order);
    BN_free(result);
    BN_CTX_free(context);
    return out;
}

class ProgrammableOracle {
  public:
    bool mark_prior(const PublicBytes &input) { return prior_.insert(input).second; }
    bool program(const PublicBytes &input, const PublicBytes &value) {
        if (prior_.count(input) != 0 || values_.count(input) != 0)
            return false;
        values_.emplace(input, value);
        return true;
    }
    PublicBytes query(const PublicBytes &input, bool nonzero) const {
        const auto found = values_.find(input);
        if (found == values_.end() || !hta::valid_public_scalar(found->second) ||
            (nonzero && std::all_of(found->second.begin(), found->second.end(),
                                    [](std::uint8_t byte) { return byte == 0; })))
            throw std::runtime_error("unprogrammed oracle input");
        return found->second;
    }
    const ChallengeMap &values() const { return values_; }

  private:
    std::set<PublicBytes> prior_;
    ChallengeMap values_;
};

struct Simulation {
    AuthorizationProof proof;
    std::array<PublicBytes, 3> challenge_inputs;
    std::array<PublicBytes, 3> challenges;
};

PublicBytes statement(const hta::Roster &roster, std::uint32_t threshold,
                      const PublicBytes &message, const PublicBytes &masked_key) {
    const PublicBytes digest(roster.digest.begin(), roster.digest.end());
    return hta::transcript(
        "ST", {hta::frame(2, digest), hta::frame_integer(roster.public_keys.size()),
               hta::frame_integer(threshold), hta::frame(2, message), hta::frame(4, masked_key)});
}

PublicBytes proof_prefix(const PublicBytes &st, const AuthorizationProof &proof) {
    return hta::transcript("T0", {hta::frame(2, st), hta::frame(4, proof.A), hta::frame(4, proof.S),
                                  hta::frame(4, proof.Qs)});
}

PublicBytes sum_points(const std::vector<PublicBytes> &points) {
    PublicBytes result{0};
    for (const auto &point : points)
        result = require(hta::public_point_add(result, point));
    return result;
}

PublicBytes inner_product(const std::vector<PublicBytes> &left,
                          const std::vector<PublicBytes> &right) {
    PublicBytes result(32, 0);
    for (std::size_t i = 0; i < left.size(); ++i)
        result = require(hta::public_scalar_add(
            result, require(hta::public_scalar_multiply(left[i], right[i]))));
    return result;
}

std::optional<Simulation> simulate(const hta::Roster &roster, const PublicBytes &context,
                                   std::uint32_t threshold, const PublicBytes &message,
                                   const PublicBytes &masked_key,
                                   const std::array<PublicBytes, 3> &challenges,
                                   ProgrammableOracle &oracle) {
    try {
        const auto dims =
            hta::dimensions(static_cast<std::uint32_t>(roster.public_keys.size()), threshold);
        if (!dims)
            return std::nullopt;
        const auto x = challenges[2];
        const auto y = challenges[0];
        const auto z = challenges[1];
        const auto inv_x = inverse(x);
        const auto gens_h0 = hta::derive_generator_secp256k1(context, dims->N, 1);
        std::vector<PublicBytes> generators_g, generators_h;
        for (std::uint32_t i = 0; i < dims->N; ++i)
            generators_g.push_back(hta::derive_generator_secp256k1(context, dims->N, i + 2));
        for (std::uint32_t i = 0; i < dims->N; ++i)
            generators_h.push_back(
                hta::derive_generator_secp256k1(context, dims->N, dims->N + i + 2));
        std::vector<PublicBytes> padded_keys = roster.public_keys;
        padded_keys.insert(padded_keys.end(), dims->ell, PublicBytes{0});
        const PublicBytes base{2,    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
                               0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
                               0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
        padded_keys.push_back(base);

        std::vector<PublicBytes> v_l, v_r;
        for (std::uint32_t i = 0; i < dims->N; ++i) {
            v_l.push_back(scalar(static_cast<std::uint8_t>(i + 3)));
            v_r.push_back(scalar(static_cast<std::uint8_t>(i + 13)));
        }
        const auto mu = scalar(23);
        const auto tau_x = scalar(29);
        AuthorizationProof proof;
        proof.A = require(hta::public_generator_multiply(scalar(31)));
        proof.T2 = require(hta::public_generator_multiply(scalar(37)));
        proof.vL = v_l;
        proof.vR = v_r;
        proof.mu = mu;
        proof.tau_x = tau_x;

        const auto qs_msm = hta::public_msm(padded_keys, v_l);
        if (!qs_msm)
            return std::nullopt;
        // Eq. (32): Qs = x^-1 <vL, PKpad> - Qe.
        const auto q_difference = require(hta::public_point_add(
            *qs_msm, require(hta::public_point_multiply(masked_key, negative_one()))));
        proof.Qs = require(hta::public_point_multiply(q_difference, inv_x));

        const auto mu_h0 = require(hta::public_point_multiply(gens_h0, mu));
        const auto g_msm = hta::public_msm(generators_g, v_l);
        const auto h_msm = hta::public_msm(generators_h, v_r);
        if (!g_msm || !h_msm)
            return std::nullopt;
        const auto s_difference = sum_points(
            {mu_h0, *g_msm, *h_msm, require(hta::public_point_multiply(proof.A, negative_one()))});
        proof.S = require(hta::public_point_multiply(s_difference, inv_x));

        std::vector<PublicBytes> y_powers(dims->N, scalar(1));
        for (std::size_t i = 1; i < y_powers.size(); ++i)
            y_powers[i] = require(hta::public_scalar_multiply(y_powers[i - 1], y));
        std::vector<PublicBytes> chi(dims->N, scalar(0)), weights(dims->N, scalar(0));
        for (std::size_t i = 0; i < roster.public_keys.size() + dims->ell; ++i)
            chi[i] = scalar(1);
        for (std::size_t i = 0; i < roster.public_keys.size(); ++i)
            weights[i] = scalar(1);
        for (std::uint32_t j = 0; j < dims->ell; ++j) {
            PublicBytes power(32, 0);
            power.back() = static_cast<std::uint8_t>(1U << j);
            weights[roster.public_keys.size() + j] =
                require(hta::public_scalar_subtract(PublicBytes(32, 0), power));
        }
        const auto z2 = require(hta::public_scalar_multiply(z, z));
        std::vector<PublicBytes> left, right;
        for (std::size_t i = 0; i < dims->N; ++i) {
            const auto zchi = require(hta::public_scalar_multiply(z, chi[i]));
            left.push_back(require(hta::public_scalar_subtract(v_l[i], zchi)));
            const auto right_base = require(hta::public_scalar_add(v_r[i], zchi));
            right.push_back(require(hta::public_scalar_add(
                require(hta::public_scalar_multiply(y_powers[i], right_base)),
                require(hta::public_scalar_multiply(z2, weights[i])))));
        }
        proof.t_hat = inner_product(left, right);

        PublicBytes chi_y(32, 0), chi_w(32, 0);
        for (std::size_t i = 0; i < roster.public_keys.size() + dims->ell; ++i)
            chi_y = require(hta::public_scalar_add(chi_y, y_powers[i]));
        for (std::size_t i = 0; i < dims->N; ++i)
            chi_w = require(hta::public_scalar_add(
                chi_w, require(hta::public_scalar_multiply(chi[i], weights[i]))));
        const auto z3 = require(hta::public_scalar_multiply(z2, z));
        auto delta = require(
            hta::public_scalar_multiply(require(hta::public_scalar_subtract(z, z2)), chi_y));
        delta = require(
            hta::public_scalar_subtract(delta, require(hta::public_scalar_multiply(z3, chi_w))));
        const auto theta = require(hta::public_scalar_add(
            require(hta::public_scalar_multiply(z2, scalar(static_cast<std::uint8_t>(threshold)))),
            delta));
        const auto x2 = require(hta::public_scalar_multiply(x, x));
        const auto first = require(hta::public_point_multiply(
            base, require(hta::public_scalar_subtract(proof.t_hat, theta))));
        const auto second = require(hta::public_point_multiply(gens_h0, tau_x));
        const auto third = require(hta::public_point_multiply(proof.T2, x2));
        const auto t1_numerator =
            sum_points({first, second, require(hta::public_point_multiply(third, negative_one()))});
        proof.T1 = require(hta::public_point_multiply(t1_numerator, inv_x));

        const auto st = statement(roster, threshold, message, masked_key);
        const auto t0 = proof_prefix(st, proof);
        const auto y_input = hta::transcript("Y", {hta::frame(2, t0)});
        const auto z_input = hta::transcript("Z", {hta::frame(2, t0), hta::frame(5, y)});
        const auto x_input =
            hta::transcript("X", {hta::frame(2, t0), hta::frame(5, y), hta::frame(5, z),
                                  hta::frame(4, proof.T1), hta::frame(4, proof.T2)});
        if (!oracle.program(y_input, y) || !oracle.program(z_input, z) ||
            !oracle.program(x_input, x))
            return std::nullopt;
        return Simulation{proof, {y_input, z_input, x_input}, challenges};
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace

int main() {
    // Small valid statement: PK_1 + PK_2 + xi*G, with threshold two.
    const auto sk1 = hta::SecretScalar::from_canonical([&] {
        std::array<std::uint8_t, 32> a{};
        a.back() = 7;
        return a;
    }());
    const auto sk2 = hta::SecretScalar::from_canonical([&] {
        std::array<std::uint8_t, 32> a{};
        a.back() = 11;
        return a;
    }());
    const auto xi = hta::SecretScalar::from_canonical([&] {
        std::array<std::uint8_t, 32> a{};
        a.back() = 13;
        return a;
    }());
    const hta::PublicBytes registry{'s', 'i', 'm'};
    const auto r1 = hta::create_registration(sk1, 1, registry);
    const auto r2 = hta::create_registration(sk2, 2, registry);
    const auto roster = hta::build_roster({r1, r2}, registry);
    const hta::PublicBytes message{'m'};
    if (!roster)
        return 1;
    const auto selected = hta::public_point_add(roster->public_keys[0], roster->public_keys[1]);
    const auto masked = selected
                            ? hta::public_point_add(*selected, hta::secret_generator_multiply(xi))
                            : std::nullopt;
    if (!selected || !masked)
        return 1;
    ProgrammableOracle oracle;
    const std::array<PublicBytes, 3> challenges{scalar(5), scalar(7), scalar(11)};
    const auto simulated =
        simulate(*roster, {'s', 'i', 'm', '-', 'g'}, 2, message, *masked, challenges, oracle);
    if (!simulated) {
        std::cerr << "simulation construction failed\n";
        return 1;
    }
    const auto challenge = [&oracle](const PublicBytes &input, bool nonzero) {
        return oracle.query(input, nonzero);
    };
    if (!hta::testing::verify_authorization_with_challenges(
            *roster, {'s', 'i', 'm', '-', 'g'}, 2, message, *masked, simulated->proof, challenge)) {
        std::cerr << "simulated proof rejected\n";
        return 1;
    }
    for (std::size_t conflict = 0; conflict < 3; ++conflict) {
        ProgrammableOracle conflicted;
        if (!conflicted.mark_prior(simulated->challenge_inputs[conflict])) {
            std::cerr << "conflict setup failed\n";
            return 1;
        }
        if (simulate(*roster, {'s', 'i', 'm', '-', 'g'}, 2, message, *masked, challenges,
                     conflicted)) {
            std::cerr << "simulator ignored conflict " << conflict << "\n";
            return 1;
        }
    }
    return 0;
}
