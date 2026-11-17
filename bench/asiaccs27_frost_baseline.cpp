#include "hta/expand_message.hpp"
#include "hta/secp256k1_public.hpp"
#include "hta/secret_group.hpp"
#include "hta/secret_scalar.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace hta;
using Clock = std::chrono::steady_clock;
using Bytes = PublicBytes;

namespace {
constexpr char context[] = "FROST-secp256k1-SHA256-v1";
std::uint64_t elapsed(Clock::time_point start) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count();
}
Bytes from_hex(const std::string &hex) {
    if ((hex.size() & 1) != 0) throw std::runtime_error("odd hex length");
    Bytes out;
    for (std::size_t i = 0; i < hex.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return out;
}
std::array<std::uint8_t, 32> array32(const Bytes &bytes) {
    if (bytes.size() != 32) throw std::runtime_error("expected scalar bytes");
    std::array<std::uint8_t, 32> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}
SecretScalar secret(const Bytes &bytes) { return SecretScalar::from_canonical(array32(bytes)); }
Bytes bytes(const SecretScalar &scalar) {
    return Bytes(scalar.bytes().begin(), scalar.bytes().end());
}
Bytes id_bytes(std::uint64_t id) {
    Bytes out(32, 0);
    for (std::size_t i = 0; i < 8; ++i) out[31 - i] = static_cast<std::uint8_t>(id >> (8 * i));
    return out;
}
Bytes sha256(const Bytes &input) {
    Bytes output(32);
    unsigned int length = 0;
    if (EVP_Digest(input.data(), input.size(), output.data(), &length, EVP_sha256(), nullptr) != 1 ||
        length != output.size()) throw std::runtime_error("SHA-256 failed");
    return output;
}
Bytes hash_to_scalar(const Bytes &input, const char *label) {
    Bytes dst(context, context + sizeof(context) - 1);
    dst.insert(dst.end(), label, label + std::char_traits<char>::length(label));
    const auto uniform = expand_message_xmd_sha256(input, dst, 48);
    using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
    BIGNUM *order_raw = nullptr;
    if (!BN_hex2bn(&order_raw, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
        throw std::runtime_error("group order initialization failed");
    BNPtr order(order_raw, BN_free), wide(BN_bin2bn(uniform.data(), uniform.size(), nullptr), BN_free),
        reduced(BN_new(), BN_free);
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    if (!wide || !reduced || !ctx || !BN_nnmod(reduced.get(), wide.get(), order.get(), ctx.get()))
        throw std::runtime_error("FROST hash-to-scalar failed");
    Bytes result(32);
    if (BN_bn2binpad(reduced.get(), result.data(), 32) != 32)
        throw std::runtime_error("FROST scalar encoding failed");
    return result;
}
Bytes inverse(const Bytes &value) {
    using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
    BIGNUM *order_raw = nullptr;
    if (!BN_hex2bn(&order_raw, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))
        throw std::runtime_error("group order initialization failed");
    BNPtr order(order_raw, BN_free), v(BN_bin2bn(value.data(), value.size(), nullptr), BN_free);
    CtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    if (!v || !ctx) throw std::runtime_error("scalar inverse allocation failed");
    BNPtr inv(BN_mod_inverse(nullptr, v.get(), order.get(), ctx.get()), BN_free);
    if (!inv) throw std::runtime_error("zero Lagrange denominator");
    Bytes result(32);
    if (BN_bn2binpad(inv.get(), result.data(), 32) != 32)
        throw std::runtime_error("scalar inverse encoding failed");
    return result;
}
Bytes lagrange(std::uint64_t id, const std::vector<std::uint64_t> &participants) {
    Bytes numerator(32, 0), denominator(32, 0);
    numerator.back() = denominator.back() = 1;
    const Bytes xi = id_bytes(id);
    if (std::find(participants.begin(), participants.end(), id) == participants.end())
        throw std::runtime_error("participant missing from Lagrange set");
    for (const auto j : participants) {
        if (j == id) continue;
        const auto xj = id_bytes(j);
        auto num = public_scalar_multiply(numerator, xj);
        auto delta = public_scalar_subtract(xj, xi);
        auto den = delta ? public_scalar_multiply(denominator, *delta) : std::nullopt;
        if (!num || !den) throw std::runtime_error("Lagrange arithmetic failed");
        numerator = *num;
        denominator = *den;
    }
    auto result = public_scalar_multiply(numerator, inverse(denominator));
    if (!result) throw std::runtime_error("Lagrange coefficient failed");
    return *result;
}
SecretScalar nonce_generate(const SecretScalar &share) {
    std::array<std::uint8_t, 32> random{};
    if (RAND_bytes(random.data(), random.size()) != 1) throw std::runtime_error("RNG failed");
    Bytes input(random.begin(), random.end());
    const auto encoded_share = bytes(share);
    input.insert(input.end(), encoded_share.begin(), encoded_share.end());
    return secret(hash_to_scalar(input, "nonce"));
}
struct Commitment { Bytes hiding; Bytes binding; };
struct Nonces {
    SecretScalar hiding;
    SecretScalar binding;
    Nonces(SecretScalar h, SecretScalar b) : hiding(std::move(h)), binding(std::move(b)) {}
};
struct Sample {
    std::uint64_t round1_ns=0, binding_factors_ns=0, group_commitment_ns=0,
                  round2_ns=0, share_verify_ns=0, aggregate_ns=0, verify_ns=0;
    std::size_t signature_bytes=65;
};

bool rfc9591_self_test() {
    const auto fail=[](const char *stage){std::cerr<<"RFC 9591 self-test mismatch: "<<stage<<'\n';return false;};
    const auto share1 = secret(from_hex("08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c"));
    const auto share3 = secret(from_hex("00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc"));
    auto nonce_from = [](const SecretScalar &sk, const char *random) {
        auto input=from_hex(random); const auto encoded=bytes(sk); input.insert(input.end(),encoded.begin(),encoded.end());
        return secret(hash_to_scalar(input,"nonce"));
    };
    auto d1=nonce_from(share1,"7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2");
    auto e1=nonce_from(share1,"47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5");
    auto d3=nonce_from(share3,"e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544");
    auto e3=nonce_from(share3,"7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9");
    if(bytes(d1)!=from_hex("841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0") ||
       bytes(e1)!=from_hex("8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80") ||
       bytes(d3)!=from_hex("2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2") ||
       bytes(e3)!=from_hex("7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98")) return fail("nonce derivation");
    Commitment c1{secret_generator_multiply(d1),secret_generator_multiply(e1)};
    Commitment c3{secret_generator_multiply(d3),secret_generator_multiply(e3)};
    if(c1.hiding!=from_hex("03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904") ||
       c1.binding!=from_hex("02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e") ||
       c3.hiding!=from_hex("03077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef6") ||
       c3.binding!=from_hex("02ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135")) return fail("nonce commitments");
    const auto group_key=from_hex("02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f");
    Bytes list=id_bytes(1); list.insert(list.end(),c1.hiding.begin(),c1.hiding.end()); list.insert(list.end(),c1.binding.begin(),c1.binding.end());
    auto id3=id_bytes(3); list.insert(list.end(),id3.begin(),id3.end()); list.insert(list.end(),c3.hiding.begin(),c3.hiding.end()); list.insert(list.end(),c3.binding.begin(),c3.binding.end());
    Bytes h4(context,context+sizeof(context)-1); h4.insert(h4.end(),{'m','s','g'}); h4.insert(h4.end(),{'t','e','s','t'});
    const auto msg_hash=sha256(h4);
    Bytes h5(context,context+sizeof(context)-1); h5.insert(h5.end(),{'c','o','m'}); h5.insert(h5.end(),list.begin(),list.end());
    const auto commitment_hash=sha256(h5);
    Bytes prefix=group_key; prefix.insert(prefix.end(),msg_hash.begin(),msg_hash.end()); prefix.insert(prefix.end(),commitment_hash.begin(),commitment_hash.end());
    Bytes in1=prefix; auto id1=id_bytes(1); in1.insert(in1.end(),id1.begin(),id1.end());
    Bytes in3=prefix; in3.insert(in3.end(),id3.begin(),id3.end());
    auto rho1=hash_to_scalar(in1,"rho"), rho3=hash_to_scalar(in3,"rho");
    if(rho1!=from_hex("3e08fe561e075c653cbfd46908a10e7637c70c74f0a77d5fd45d1a750c739ec6") ||
       rho3!=from_hex("93f79041bb3fd266105be251adaeb5fd7f8b104fb554a4ba9a0becea48ddbfd7")) return fail("binding factors");
    auto re1=public_point_multiply(c1.binding,rho1), re3=public_point_multiply(c3.binding,rho3);
    auto r=public_point_add(c1.hiding,*re1); r=r?public_point_add(*r,c3.hiding):std::nullopt; r=r?public_point_add(*r,*re3):std::nullopt;
    if(!r || *r!=from_hex("0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0")) return fail("group commitment");
    Bytes cinput=*r; cinput.insert(cinput.end(),group_key.begin(),group_key.end()); cinput.insert(cinput.end(),{'t','e','s','t'});
    auto challenge=hash_to_scalar(cinput,"chal");
    auto lambda1=lagrange(1,{1,3}), lambda3=lagrange(3,{1,3});
    auto response=[&](const SecretScalar&d,const SecretScalar&e,const SecretScalar&sk,const Bytes&rho,const Bytes&lambda){
        auto bind=secret_scalar_multiply(secret(rho),e);
        auto key=secret_scalar_multiply(secret(lambda),sk);
        key=secret_scalar_multiply(secret(challenge),key);
        return bytes(secret_scalar_add(secret_scalar_add(d,bind),key));
    };
    auto z1=response(d1,e1,share1,rho1,lambda1), z3=response(d3,e3,share3,rho3,lambda3);
    if(z1!=from_hex("c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197") ||
       z3!=from_hex("0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d")) {
        for(auto x:z1)std::cerr<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(x);std::cerr<<' ';for(auto x:z3)std::cerr<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(x);std::cerr<<'\n';return fail("signature shares");
    }
    auto z=public_scalar_add(z1,z3);
    Bytes signature=*r; signature.insert(signature.end(),z->begin(),z->end());
    return signature==from_hex("0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324") || fail("aggregate signature");
}

Sample sign_once(const std::vector<SecretScalar> &shares, const std::vector<Bytes> &public_shares,
                 const std::vector<Bytes> &lambdas, const Bytes &group_key, std::uint32_t t,
                 const Bytes &message) {
    Sample sample;
    std::vector<Nonces> nonces;
    std::vector<Commitment> commitments;
    nonces.reserve(t); commitments.reserve(t);
    auto start=Clock::now();
    for(std::uint32_t i=0;i<t;++i){
        auto d=nonce_generate(shares[i]), e=nonce_generate(shares[i]);
        commitments.push_back({secret_generator_multiply(d),secret_generator_multiply(e)});
        nonces.emplace_back(std::move(d),std::move(e));
    }
    sample.round1_ns=elapsed(start);
    Bytes list; list.reserve(static_cast<std::size_t>(t)*98);
    for(std::uint32_t i=0;i<t;++i){auto id=id_bytes(i+1);list.insert(list.end(),id.begin(),id.end());list.insert(list.end(),commitments[i].hiding.begin(),commitments[i].hiding.end());list.insert(list.end(),commitments[i].binding.begin(),commitments[i].binding.end());}
    Bytes h4(context,context+sizeof(context)-1); h4.insert(h4.end(),{'m','s','g'}); h4.insert(h4.end(),message.begin(),message.end());
    const auto msg_hash=sha256(h4);
    Bytes h5(context,context+sizeof(context)-1); h5.insert(h5.end(),{'c','o','m'}); h5.insert(h5.end(),list.begin(),list.end());
    const auto commitment_hash=sha256(h5);
    Bytes prefix=group_key; prefix.insert(prefix.end(),msg_hash.begin(),msg_hash.end()); prefix.insert(prefix.end(),commitment_hash.begin(),commitment_hash.end());
    start=Clock::now(); std::vector<Bytes> rho; rho.reserve(t);
    for(std::uint32_t i=0;i<t;++i){auto input=prefix;auto id=id_bytes(i+1);input.insert(input.end(),id.begin(),id.end());rho.push_back(hash_to_scalar(input,"rho"));}
    sample.binding_factors_ns=elapsed(start);
    start=Clock::now(); Bytes R{0};
    for(std::uint32_t i=0;i<t;++i){auto weighted=public_point_multiply(commitments[i].binding,rho[i]);auto sum=weighted?public_point_add(commitments[i].hiding,*weighted):std::nullopt;sum=sum?public_point_add(R,*sum):std::nullopt;if(!sum)throw std::runtime_error("FROST group commitment failed");R=*sum;}
    sample.group_commitment_ns=elapsed(start);
    if(!valid_public_point(R,false))throw std::runtime_error("FROST identity group commitment");
    Bytes cinput=R;cinput.insert(cinput.end(),group_key.begin(),group_key.end());cinput.insert(cinput.end(),message.begin(),message.end());
    const auto challenge=hash_to_scalar(cinput,"chal");
    start=Clock::now(); std::vector<Bytes> responses;responses.reserve(t);
    for(std::uint32_t i=0;i<t;++i){auto bind=secret_scalar_multiply(secret(rho[i]),nonces[i].binding);auto key=secret_scalar_multiply(secret(lambdas[i]),shares[i]);key=secret_scalar_multiply(secret(challenge),key);responses.push_back(bytes(secret_scalar_add(secret_scalar_add(nonces[i].hiding,bind),key)));}
    sample.round2_ns=elapsed(start);
    start=Clock::now();
    for(std::uint32_t i=0;i<t;++i){auto lhs=public_generator_multiply(responses[i]);auto re=public_point_multiply(commitments[i].binding,rho[i]);auto nonce=re?public_point_add(commitments[i].hiding,*re):std::nullopt;auto lc=public_scalar_multiply(lambdas[i],challenge);auto key=lc?public_point_multiply(public_shares[i],*lc):std::nullopt;auto rhs=nonce&&key?public_point_add(*nonce,*key):std::nullopt;if(!lhs||!rhs||*lhs!=*rhs)throw std::runtime_error("invalid FROST share");}
    sample.share_verify_ns=elapsed(start);
    start=Clock::now(); Bytes z(32,0);for(const auto &response:responses){auto sum=public_scalar_add(z,response);if(!sum)throw std::runtime_error("FROST response aggregate failed");z=*sum;}sample.aggregate_ns=elapsed(start);
    start=Clock::now();auto lhs=public_generator_multiply(z);auto rc=public_point_multiply(group_key,challenge);auto rhs=rc?public_point_add(R,*rc):std::nullopt;if(!lhs||!rhs||*lhs!=*rhs)throw std::runtime_error("FROST signature verification failed");sample.verify_ns=elapsed(start);
    return sample;
}
} // namespace

int main(int argc,char **argv){
    try {
        if(argc==2 && std::string(argv[1])=="--self-test") return rfc9591_self_test()?0:1;
        if(argc!=3)throw std::runtime_error("usage: asiaccs27_frost_baseline n samples");
        if(!rfc9591_self_test())throw std::runtime_error("RFC 9591 Appendix E.5 vector failed");
        const auto n=static_cast<std::uint32_t>(std::stoul(argv[1]));
        const auto samples=static_cast<std::uint32_t>(std::stoul(argv[2]));
        if(n<2||n>4096||samples<100||samples>10000)throw std::runtime_error("invalid n or samples");
        const auto t=(2*n+2)/3;
        auto setup=Clock::now();std::vector<SecretScalar> coefficients;coefficients.reserve(t);
        coefficients.push_back(random_secret_scalar());for(std::uint32_t j=1;j<t;++j)coefficients.push_back(random_secret_scalar_allow_zero());
        std::vector<SecretScalar> shares;std::vector<Bytes> public_shares;shares.reserve(n);public_shares.reserve(n);
        for(std::uint32_t id=1;id<=n;++id){auto x=secret(id_bytes(id));auto value=SecretScalar::from_canonical(coefficients.back().bytes());for(std::uint32_t j=t-1;j>0;--j)value=secret_scalar_add(secret_scalar_multiply(value,x),coefficients[j-1]);shares.push_back(std::move(value));public_shares.push_back(secret_generator_multiply(shares.back()));}
        const auto group_key=secret_generator_multiply(coefficients[0]);const auto setup_ns=elapsed(setup);
        std::vector<std::uint64_t> participants;for(std::uint32_t i=1;i<=t;++i)participants.push_back(i);
        std::vector<Bytes> lambdas;for(const auto i:participants)lambdas.push_back(lagrange(i,participants));
        const Bytes message(32,0x42);constexpr std::uint32_t warmups=10;
        for(std::uint32_t i=0;i<samples+warmups;++i){auto sample=sign_once(shares,public_shares,lambdas,group_key,t,message);if(i>=warmups)std::cout<<"{\"n\":"<<n<<",\"t\":"<<t<<",\"sample\":"<<(i-warmups)<<",\"dealer_setup_ns\":"<<setup_ns<<",\"round1_total_ns\":"<<sample.round1_ns<<",\"round1_per_signer_ns\":"<<sample.round1_ns/t<<",\"binding_factors_ns\":"<<sample.binding_factors_ns<<",\"group_commitment_ns\":"<<sample.group_commitment_ns<<",\"round2_total_ns\":"<<sample.round2_ns<<",\"round2_per_signer_ns\":"<<sample.round2_ns/t<<",\"share_verify_ns\":"<<sample.share_verify_ns<<",\"aggregate_ns\":"<<sample.aggregate_ns<<",\"verify_ns\":"<<sample.verify_ns<<",\"signature_bytes\":"<<sample.signature_bytes<<",\"public_group_info_bytes\":"<<(33ULL*(n+1))<<"}\n";}
    } catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}
    return 0;
}
