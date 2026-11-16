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
#include <chrono>
#include <memory>
#include <mutex>
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
    PublicBytes H0, Gxi, Gip;
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
    result.Gxi = derive_generator_secp256k1(context, N, 2*N+2);
    result.Gip = derive_generator_secp256k1(context, N, 2*N+3);
    result.G.reserve(N);
    result.H.reserve(N);
    for (std::uint32_t i = 0; i < N; ++i)
        result.G.push_back(derive_generator_secp256k1(context, N, i + 2));
    for (std::uint32_t i = 0; i < N; ++i)
        result.H.push_back(derive_generator_secp256k1(context, N, N + i + 2));
    return result;
}

std::shared_ptr<const Generators> get_generators(const PublicBytes &context, std::uint32_t N) {
#ifdef HTA_GENERATOR_CACHE
    struct Entry {
        PublicBytes context;
        std::uint32_t N = 0;
        std::shared_ptr<const Generators> value;
    };
    static std::mutex mutex;
    static Entry entry;
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (entry.value && entry.N == N && entry.context == context)
            return entry.value;
    }
#endif
    auto value = std::make_shared<const Generators>(derive_generators(context, N));
#ifdef HTA_GENERATOR_CACHE
    {
        std::lock_guard<std::mutex> lock(mutex);
        entry.context = context;
        entry.N = N;
        entry.value = value;
    }
#endif
    return value;
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
                      const PublicBytes &message, const PublicBytes &masked_key, const PublicBytes &context, std::uint32_t N, std::uint32_t r) {
    const auto cfg = transcript("CONFIG", {frame(2,context),frame_integer(N),frame_integer(r)});
    return transcript("ST", {frame(2,cfg), frame(2, digest), frame_integer(n), frame_integer(threshold),
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
    for (std::size_t i = 0; i < dims.N; ++i)
        chi[i] = one;
    for (std::size_t i = 0; i < n; ++i)
        w[i] = one;
    for (std::uint32_t j = 0; j < dims.ell; ++j) {
        PublicBytes power(32, 0);
        power[power.size() - 1 - j / 8] = static_cast<std::uint8_t>(1U << (j % 8));
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

PublicBytes addf(const PublicBytes&a,const PublicBytes&b){return must(public_scalar_add(a,b));}
PublicBytes subf(const PublicBytes&a,const PublicBytes&b){return must(public_scalar_subtract(a,b));}
PublicBytes mulf(const PublicBytes&a,const PublicBytes&b){return must(public_scalar_multiply(a,b));}
PublicBytes num(std::uint64_t n){return public_bytes(scalar_value(n));}
PublicBytes inv(const PublicBytes&a){
 if(a==num(0)) throw std::invalid_argument("zero inverse");
 const unsigned char exponent[32]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x3f};
 auto out=num(1); for(auto byte:exponent) for(int bit=7;bit>=0;--bit){out=mulf(out,out);if((byte>>bit)&1)out=mulf(out,a);}return out;
}
SecretScalar secret(const PublicBytes&a){std::array<std::uint8_t,32>b{};std::copy(a.begin(),a.end(),b.begin());return SecretScalar::from_canonical(b);}
PublicBytes tpsi(const PublicBytes&T0,const PublicBytes&y,const PublicBytes&z,const PublicBytes&x,const AuthorizationProof&p){
 return transcript("TPSI",{frame(2,T0),frame(5,y),frame(5,z),frame(4,p.T1),frame(4,p.T2),frame(5,x),frame(5,p.t_hat),frame(5,p.mu),frame(5,p.mu_xi),frame(5,p.tau_x)});
}
PublicBytes fold_input(const PublicBytes&tau,const std::vector<PublicBytes>&u,const AuthorizationProof&p,std::size_t j){
 PublicBytes us,lr;for(auto &v:u){auto f=frame(5,v);us.insert(us.end(),f.begin(),f.end());}
 for(std::size_t i=0;i<=j;++i)for(auto v:{p.L[i],p.R[i]}){auto f=frame(4,v);lr.insert(lr.end(),f.begin(),f.end());}
 return transcript("UPSILON",{frame_integer(j+1),frame(2,tau),frame(6,us),frame(6,lr)});
}
PublicBytes proof_encoding(const AuthorizationProof&p){
 PublicBytes folds,left,right;
 for(std::size_t i=0;i<p.L.size();++i)for(const auto *v:{&p.L[i],&p.R[i]}){auto f=frame(4,*v);folds.insert(folds.end(),f.begin(),f.end());}
 for(const auto&v:p.vL){auto f=frame(5,v);left.insert(left.end(),f.begin(),f.end());}
 for(const auto&v:p.vR){auto f=frame(5,v);right.insert(right.end(),f.begin(),f.end());}
 return transcript("PROOF",{frame_integer(p.r),frame(4,p.A),frame(4,p.S),frame(4,p.Qs),frame(4,p.T1),frame(4,p.T2),frame(5,p.t_hat),frame(5,p.mu),frame(5,p.mu_xi),frame(5,p.tau_x),frame(6,folds),frame(6,left),frame(6,right)});
}

} // namespace

std::optional<AuthorizationProof>
prove_authorization(const Roster &roster, const PublicBytes &generator_context,
                    std::uint32_t threshold, const PublicBytes &message,
                    const PublicBytes &masked_key, const std::vector<std::uint8_t> &selectors,
                    const std::vector<std::uint8_t> &surplus_bits,
                    // Move-only ownership transfer keeps secret cleanup local to this call.
                    // cppcheck-suppress passedByValue
                    SecretScalar tweak, std::uint32_t r, ProofTimings *timings) {
    const auto total_start = timings ? std::chrono::steady_clock::now()
                                    : std::chrono::steady_clock::time_point{};
    if (timings)
        *timings = {};
    const auto params = validate_public(roster, generator_context, threshold, message, masked_key);
    if (!params || r > params->dims.kappa || !tweak.valid(false) || selectors.size() != roster.public_keys.size() ||
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
        const auto gens = get_generators(generator_context, params->dims.N);
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
        while(aL.size()<params->dims.N){aL.push_back(zero_scalar());aR.push_back(secret_scalar_subtract(zero_scalar(),one));}

        const auto selected_public = secret_msm(roster.public_keys, selected_scalars);
        const auto tweak_public = secret_generator_multiply(tweak);
        const auto linked_key = must(public_point_add(selected_public, tweak_public));
        if (linked_key != masked_key)
            return std::nullopt;

        const auto commitments_start = timings ? std::chrono::steady_clock::now()
                                               : std::chrono::steady_clock::time_point{};
        auto alpha = random_secret_scalar_allow_zero();
        auto rho = random_secret_scalar_allow_zero();
        auto rho_xi = random_secret_scalar_allow_zero();
        auto tau1 = random_secret_scalar_allow_zero();
        auto tau2 = random_secret_scalar_allow_zero();
        std::vector<SecretScalar> sL, sR;
        sL.reserve(params->dims.N);
        sR.reserve(params->dims.N);
        for (std::uint32_t i = 0; i < params->dims.N; ++i) {
            sL.push_back(random_secret_scalar_allow_zero());
            sR.push_back(random_secret_scalar_allow_zero());
        }

        std::vector<PublicBytes> a_points{gens->H0};
        a_points.insert(a_points.end(), gens->G.begin(), gens->G.end());
        a_points.insert(a_points.end(), gens->H.begin(), gens->H.end());
        std::vector<SecretScalar> a_scalars;
        a_scalars.reserve(1 + 2 * params->dims.N);
        a_scalars.push_back(clone(alpha));
        auto left_clones = clone_vector(aL);
        auto right_clones = clone_vector(aR);
        for (auto &value : left_clones)
            a_scalars.push_back(std::move(value));
        for (auto &value : right_clones)
            a_scalars.push_back(std::move(value));
        a_points.push_back(gens->Gxi);
        a_scalars.push_back(clone(tweak));
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
        s_scalars.push_back(clone(rho_xi));
        const auto Scom = secret_msm(a_points, s_scalars);

        std::vector<PublicBytes> padded_keys = roster.public_keys;
        padded_keys.resize(params->dims.N, PublicBytes{0});
        const auto Qs = must(public_point_add(secret_msm(padded_keys, sL),secret_generator_multiply(rho_xi)));
        AuthorizationProof proof;
        proof.r=r;
        proof.A = A;
        proof.S = Scom;
        proof.Qs = Qs;
        const auto st =
            statement(params->digest, static_cast<std::uint32_t>(roster.public_keys.size()),
                      threshold, message, masked_key, generator_context, params->dims.N, r);
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
        const auto T1 = secret_msm({base_point, gens->H0}, t1_scalars);
        std::vector<SecretScalar> t2_scalars;
        t2_scalars.push_back(clone(t2));
        t2_scalars.push_back(clone(tau2));
        const auto T2 = secret_msm({base_point, gens->H0}, t2_scalars);
        proof.T1 = T1;
        proof.T2 = T2;
        if (timings)
            timings->commitments_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - commitments_start).count();
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
        proof.t_hat = public_bytes(t_hat);
        proof.mu = public_bytes(mu);
        proof.mu_xi=public_bytes(secret_scalar_add(tweak,secret_scalar_multiply(x_secret,rho_xi)));
        proof.tau_x = public_bytes(tau_x);
        const auto tp=tpsi(T0,y,z,x,proof);
        const auto psi=public_challenge(transcript("PSI",{frame(2,tp),frame_integer(0)}),true);
        const auto omega=public_challenge(transcript("PSI",{frame(2,tp),frame_integer(1)}),true);
        const auto tau=transcript("FOLDCTX",{frame(2,tp),frame(5,psi),frame(5,omega)});
        auto g=gens->G,h=gens->H;
        auto yi=powers(inv(y),params->dims.N);
        for(std::size_t i=0;i<g.size();++i){g[i]=must(public_msm({g[i],padded_keys[i]},{num(1),psi}));h[i]=must(public_point_multiply(h[i],yi[i]));}
        const auto U=must(public_point_multiply(gens->Gip,omega));
        auto a=std::move(c3_left),b=std::move(c3_right);
        std::vector<PublicBytes> challenges;
        if (timings)
            timings->folding_round_ns.reserve(r);
        for(std::uint32_t j=0;j<r;++j){
          const auto round_start = timings ? std::chrono::steady_clock::now()
                                           : std::chrono::steady_clock::time_point{};
          const auto m=a.size()/2;
          std::vector<SecretScalar> al,ah,bl,bh;
          std::vector<PublicBytes> gl(g.begin(),g.begin()+m),gh(g.begin()+m,g.end()),hl(h.begin(),h.begin()+m),hh(h.begin()+m,h.end());
          for(std::size_t i=0;i<m;++i){al.push_back(clone(a[i]));ah.push_back(clone(a[i+m]));bl.push_back(clone(b[i]));bh.push_back(clone(b[i+m]));}
          proof.L.push_back(must(public_point_add(must(public_point_add(secret_msm(gh,al),secret_msm(hl,bh))),secret_point_multiply(U,secret_inner_product(al,bh)))));
          proof.R.push_back(must(public_point_add(must(public_point_add(secret_msm(gl,ah),secret_msm(hh,bl))),secret_point_multiply(U,secret_inner_product(ah,bl)))));
          const auto u=public_challenge(fold_input(tau,challenges,proof,j),true),ui=inv(u);challenges.push_back(u);
          auto su=secret(u),si=secret(ui);
          std::vector<SecretScalar> na,nb;std::vector<PublicBytes> ng,nh;
          for(std::size_t i=0;i<m;++i){
            na.push_back(secret_scalar_add(secret_scalar_multiply(su,al[i]),secret_scalar_multiply(si,ah[i])));
            nb.push_back(secret_scalar_add(secret_scalar_multiply(si,bl[i]),secret_scalar_multiply(su,bh[i])));
            ng.push_back(must(public_msm({gl[i],gh[i]},{ui,u})));nh.push_back(must(public_msm({hl[i],hh[i]},{u,ui})));
          }a=std::move(na);b=std::move(nb);g=std::move(ng);h=std::move(nh);
          if (timings)
            timings->folding_round_ns.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - round_start).count());
        }
        for(const auto &v:a)proof.vL.push_back(public_bytes(v));
        for(const auto &v:b)proof.vR.push_back(public_bytes(v));
        if (timings) {
            timings->total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - total_start).count();
            std::uint64_t folding_ns = 0;
            for (const auto ns : timings->folding_round_ns)
                folding_ns += ns;
            timings->other_proof_ns = timings->total_ns - timings->commitments_ns - folding_ns;
        }
        return proof;
    } catch (...) {
        return std::nullopt;
    }
}

namespace {
template <typename ChallengeProvider>
bool verify_authorization_impl(const Roster&roster,const PublicBytes&context,std::uint32_t threshold,const PublicBytes&message,const PublicBytes&key,const AuthorizationProof&p,const ChallengeProvider&challenge,std::uint32_t r,VerificationTimings*timings){
 const auto total_start=timings?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};if(timings)*timings={};
 const auto params=validate_public(roster,context,threshold,message,key);
 if(!params||r>params->dims.kappa||p.r!=r||p.L.size()!=r||p.R.size()!=r||p.vL.size()!=(params->dims.N>>r)||p.vR.size()!=p.vL.size())return false;
 for(const auto &v:{p.A,p.S,p.Qs,p.T1,p.T2})if(!valid_public_point(v,true))return false;
 for(const auto &v:{p.mu,p.mu_xi,p.t_hat,p.tau_x})if(!valid_public_scalar(v))return false;
 for(const auto *vec:{&p.L,&p.R})for(const auto &v:*vec)if(!valid_public_point(v,true))return false;
 for(const auto *vec:{&p.vL,&p.vR})for(const auto &v:*vec)if(!valid_public_scalar(v))return false;
 try{
 auto gens=get_generators(context,params->dims.N);const auto N=params->dims.N;
 auto st=statement(params->digest,roster.public_keys.size(),threshold,message,key,context,N,r),T0=proof_prefix(st,p);
 auto y=challenge(transcript("Y",{frame(2,T0)}),true),z=challenge(transcript("Z",{frame(2,T0),frame(5,y)}),true);
 auto x=challenge(transcript("X",{frame(2,T0),frame(5,y),frame(5,z),frame(4,p.T1),frame(4,p.T2)}),true);
 auto yp=powers(y,N),yi=powers(inv(y),N),w=public_chi_w(roster.public_keys.size(),params->dims).second;
 auto z2=mulf(z,z),sumy=num(0),sumw=num(0);for(std::size_t i=0;i<N;++i){sumy=addf(sumy,yp[i]);sumw=addf(sumw,w[i]);}
 auto theta=subf(addf(mulf(z2,num(threshold)),mulf(subf(z,z2),sumy)),mulf(mulf(z2,z),sumw));
 const auto v1_start=timings?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};
 const auto v1_ok=must(public_msm({base_point,gens->H0,p.T1,p.T2},{subf(p.t_hat,theta),p.tau_x,subf(num(0),x),subf(num(0),mulf(x,x))}))==PublicBytes{0};
 if(timings)timings->v1_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-v1_start).count();
 if(!v1_ok)return false;
 const auto folding_start=timings?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};
 auto tp=tpsi(T0,y,z,x,p);auto psi=challenge(transcript("PSI",{frame(2,tp),frame_integer(0)}),true),omega=challenge(transcript("PSI",{frame(2,tp),frame_integer(1)}),true);
 auto tau=transcript("FOLDCTX",{frame(2,tp),frame(5,psi),frame(5,omega)});
 std::vector<PublicBytes> us,uis;
 // Expand P-tilde (5.11), including psi times the whole parenthesized linkage term.
 std::vector<PublicBytes> points{p.A,p.S,gens->H0,gens->Gxi,key,p.Qs,base_point,gens->Gip};
 std::vector<PublicBytes> scalars{num(1),x,subf(num(0),p.mu),subf(num(0),p.mu_xi),psi,mulf(psi,x),subf(num(0),mulf(psi,p.mu_xi)),mulf(omega,subf(p.t_hat,public_inner_product(p.vL,p.vR)))};
 for(std::uint32_t j=0;j<r;++j){auto u=challenge(fold_input(tau,us,p,j),true);us.push_back(u);uis.push_back(inv(u));points.push_back(p.L[j]);scalars.push_back(mulf(u,u));points.push_back(p.R[j]);scalars.push_back(mulf(uis.back(),uis.back()));}
 const auto m=N>>r;
 for(std::size_t i=0;i<N;++i){auto si=num(1),isi=num(1);for(std::uint32_t j=0;j<r;++j){bool high=(i>>(params->dims.kappa-j-1))&1;si=mulf(si,high?us[j]:uis[j]);isi=mulf(isi,high?uis[j]:us[j]);}
 auto ga=mulf(p.vL[i%m],si);
 points.push_back(gens->G[i]);scalars.push_back(subf(subf(num(0),z),ga)); // -z<G,chi> - <a,g>
 points.push_back(gens->H[i]);scalars.push_back(mulf(yi[i],subf(addf(mulf(z,yp[i]),mulf(z2,w[i])),mulf(p.vR[i%m],isi)))); // <zy chi+z^2w,H'> - <b,h>
 if(i<roster.public_keys.size()){points.push_back(roster.public_keys[i]);scalars.push_back(subf(num(0),mulf(psi,addf(z,ga))));}
 }
 if(timings)timings->folding_scalars_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-folding_start).count();
 const auto v2_start=timings?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};
 const auto v2_ok=must(public_msm(points,scalars))==PublicBytes{0};
 if(timings){timings->v2_msm_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-v2_start).count();if(v2_ok)timings->authorization_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-total_start).count();}
 return v2_ok;
 }catch(...){return false;}
}
}
bool verify_authorization(const Roster&r,const PublicBytes&ctx,std::uint32_t t,const PublicBytes&m,const PublicBytes&key,const AuthorizationProof&p,std::uint32_t depth,VerificationTimings*timings){return verify_authorization_impl(r,ctx,t,m,key,p,public_challenge,depth,timings);}
bool testing::verify_authorization_with_challenges(const Roster&r,const PublicBytes&ctx,std::uint32_t t,const PublicBytes&m,const PublicBytes&key,const AuthorizationProof&p,const ChallengeProvider&c){return c&&verify_authorization_impl(r,ctx,t,m,key,p,c,p.r,nullptr);}
bool verify_signature(const Roster&r,const PublicBytes&ctx,std::uint32_t t,const PublicBytes&m,const FinalSignature&s,std::uint32_t depth,VerificationTimings*timings){
 try{const auto full_start=timings?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};if(timings)*timings={};if(s.authorization.r!=depth||s.authorization.L.size()!=depth||s.authorization.R.size()!=depth||!valid_public_point(s.schnorr.masked_key,false)||!valid_public_point(s.schnorr.nonce,false)||!valid_public_scalar(s.schnorr.response)||!verify_authorization(r,ctx,t,m,s.schnorr.masked_key,s.authorization,depth,timings))return false;auto bytes=proof_encoding(s.authorization);
 PublicBytes digest(r.digest.begin(),r.digest.end());auto c=public_challenge(transcript("SIG",{frame(2,digest),frame(4,s.schnorr.masked_key),frame_integer(t),frame(4,s.schnorr.nonce),frame(2,m),frame(2,bytes)}),false);
  const auto schnorr_start=timings?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};const auto ok=must(public_msm({base_point,s.schnorr.nonce,s.schnorr.masked_key},{s.schnorr.response,subf(num(0),num(1)),subf(num(0),c)}))==PublicBytes{0};if(timings){timings->schnorr_equation_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-schnorr_start).count();if(ok)timings->full_signature_ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-full_start).count();}return ok;
 }catch(...){return false;}
}
bool batch_verify_signatures(const Roster&,const PublicBytes&,std::uint32_t,const std::vector<PublicBytes>&,const std::vector<FinalSignature>&){return false;}
} // namespace hta
