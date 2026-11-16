#include "hta/authorization.hpp"
#include "hta/protocol_encoding.hpp"
#include "hta/registration.hpp"
#include "hta/parameters.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <thread>

static hta::SecretScalar sk(std::uint8_t x) {
    std::array<std::uint8_t,32> b{}; b.back()=x; return hta::SecretScalar::from_canonical(b);
}

int main() {
    using namespace hta;
    PublicBytes registry{'r'}, ctx{'g'}, sid{'s'}, msg{'m'};
    auto a=create_registration(sk(7),1,registry), b=create_registration(sk(11),2,registry);
    auto roster=build_roster({a,b},registry); if(!roster) return 1;
    auto coordinator=CoordinatorSession::begin(*roster,sid,2,msg,{1,2},sk(13),ctx,0);
    if(!coordinator) return 2;
    Signer s1(1,sk(7)),s2(2,sk(11));
    auto decoded=decode_authorization_proof(coordinator->certificate(),2,0);
    if(!decoded || !verify_authorization(*roster,ctx,2,msg,coordinator->masked_key(),*decoded,0))return 11;
    PublicBytes mask(32,0); mask.back()=13;
    Signer mask_signer(1,sk(7));
    if(!mask_signer.round1(*roster,{'m','1'},2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0,1,mask))return 15;
    if(mask_signer.round1(*roster,{'m','1'},2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0,1,mask))return 26;
    Signer bad_mask_signer(1,sk(7)); auto bad_mask=mask;bad_mask.back()=14;
    if(bad_mask_signer.round1(*roster,{'m','2'},2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0,1,bad_mask))return 16;
    Signer replay_signer(1,sk(7));
    auto bad_certificate=coordinator->certificate(); bad_certificate[0]^=1;
    if(replay_signer.round1(*roster,{'r'},2,msg,coordinator->masked_key(),{1,2},ctx,bad_certificate,0))return 27;
    if(!replay_signer.round1(*roster,{'r'},2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0))return 28;
    if(!replay_signer.cancel({'r'}) || replay_signer.round1(*roster,{'r'},2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0))return 29;
    Signer racing_signer(1,sk(7));
    std::optional<RoundOneCommitments> race_a, race_b;
    std::thread first([&]{race_a=racing_signer.round1(*roster,{'x'},2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0);});
    std::thread second([&]{race_b=racing_signer.round1(*roster,{'x'},2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0);});
    first.join(); second.join();
    if(static_cast<bool>(race_a)==static_cast<bool>(race_b) || !racing_signer.cancel({'x'}))return 30;
    auto dims=dimensions(2,2); if(!dims)return 12;
    for(std::uint32_t depth=0;depth<=dims->kappa;++depth){
        auto proof=prove_authorization(*roster,ctx,2,msg,coordinator->masked_key(),{1,1},{0,0},sk(13),depth);
        if(!proof || !verify_authorization(*roster,ctx,2,msg,coordinator->masked_key(),*proof,depth))return 13;
        auto wire=encode_authorization_proof(*proof,2,depth);
        if(!wire || !decode_authorization_proof(*wire,2,depth))return 14;

        // Equation-level regression: every transcript, commitment, fold pair, and
        // terminal scalar must be bound by V1/V2. Replacing points with another
        // valid roster point keeps these checks beyond the decoder boundary.
        auto rejects=[&](AuthorizationProof changed){
            return !verify_authorization(*roster,ctx,2,msg,coordinator->masked_key(),changed,depth);
        };
        for(auto field:{0,1,2,3,4}){
            auto changed=*proof;
            PublicBytes *point=nullptr;
            switch(field){
            case 0: point=&changed.A; break;
            case 1: point=&changed.S; break;
            case 2: point=&changed.Qs; break;
            case 3: point=&changed.T1; break;
            default: point=&changed.T2; break;
            }
            *point=(*point==roster->public_keys[0])?roster->public_keys[1]:roster->public_keys[0];
            if(!rejects(std::move(changed)))return 17;
        }
        for(auto field:{0,1,2,3}){
            auto changed=*proof;
            PublicBytes *scalar=nullptr;
            switch(field){
            case 0: scalar=&changed.t_hat; break;
            case 1: scalar=&changed.mu; break;
            case 2: scalar=&changed.mu_xi; break;
            default: scalar=&changed.tau_x; break;
            }
            scalar->back()^=1;
            if(!rejects(std::move(changed)))return 18;
        }
        for(std::size_t i=0;i<proof->L.size();++i){
            auto changed=*proof;
            changed.L[i]=(changed.L[i]==roster->public_keys[0])?roster->public_keys[1]:roster->public_keys[0];
            if(!rejects(std::move(changed)))return 19;
            changed=*proof;
            changed.R[i]=(changed.R[i]==roster->public_keys[0])?roster->public_keys[1]:roster->public_keys[0];
            if(!rejects(std::move(changed)))return 20;
        }
        for(std::size_t i=0;i<proof->vL.size();++i){
            auto changed=*proof; changed.vL[i].back()^=1;
            if(!rejects(std::move(changed)))return 21;
            changed=*proof; changed.vR[i].back()^=1;
            if(!rejects(std::move(changed)))return 22;
        }
        const auto wrong_depth=depth==dims->kappa?depth-1:depth+1;
        if(verify_authorization(*roster,ctx,2,msg,coordinator->masked_key(),*proof,wrong_depth))return 23;
        if(verify_authorization(*roster,ctx,2,{'x'},coordinator->masked_key(),*proof,depth))return 24;
        if(verify_authorization(*roster,ctx,2,msg,roster->public_keys[0],*proof,depth))return 25;
    }
    auto c1=s1.round1(*roster,sid,2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0);
    auto c2=s2.round1(*roster,sid,2,msg,coordinator->masked_key(),{1,2},ctx,coordinator->certificate(),0);
    if(!c1||!c2) return 3;
    auto agg=coordinator->collect_commitments({{1,*c1},{2,*c2}}); if(!agg)return 4;
    auto r1=s1.round2(sid,agg->first,agg->second),r2=s2.round2(sid,agg->first,agg->second);
    if(!r1||!r2||!coordinator->verify_partial_response(1,*r1)||!coordinator->verify_partial_response(2,*r2))return 5;
    if(s1.round2(sid,agg->first,agg->second))return 31;
    auto sig=coordinator->aggregate_responses({{1,*r1},{2,*r2}});if(!sig)return 6;
    auto cert=decode_authorization_proof(coordinator->certificate(),2,0);if(!cert)return 7;
    FinalSignature final{*sig,*cert};if(!verify_signature(*roster,ctx,2,msg,final,0))return 8;
    auto final_wire=encode_signature(final,2,0);
    auto final_roundtrip=final_wire?decode_signature(*final_wire,2,0):std::nullopt;
    if(!final_roundtrip || !verify_signature(*roster,ctx,2,msg,*final_roundtrip,0))return 32;
    auto altered=final; altered.authorization.mu_xi[0]^=1;
    if(verify_signature(*roster,ctx,2,msg,altered,0))return 9;
    auto malformed=final;malformed.authorization.R.push_back({0});
    if(verify_signature(*roster,ctx,2,msg,malformed,0))return 10;
    return 0;
}
