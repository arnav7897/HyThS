#include "hta/coordinator.hpp"
#include "hta/protocol_encoding.hpp"
#include "hta/parameters.hpp"
#include "hta/framing.hpp"
#include "hta/secret_group.hpp"
#include "hta/secret_scalar.hpp"
#include "hta/scalar_challenge.hpp"
#include <openssl/evp.h>
#include <chrono>
#include <array>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
using namespace hta;
using Clock=std::chrono::steady_clock;
static std::uint64_t elapsed(Clock::time_point t){return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-t).count();}
static SecretScalar secret_from(const PublicBytes&v){std::array<std::uint8_t,32>b{};std::copy(v.begin(),v.end(),b.begin());return SecretScalar::from_canonical(b);}
static PublicBytes make_context(const PublicBytes&sid,const PublicBytes&digest,std::uint32_t t,const PublicBytes&msg,const PublicBytes&key,const std::vector<std::uint64_t>&subset,const PublicBytes&cert){PublicBytes p;for(auto i:subset){auto f=frame_integer(i);p.insert(p.end(),f.begin(),f.end());}auto s=transcript("SUBSET",{frame(6,p)});return transcript("CTX",{frame(2,sid),frame(2,digest),frame_integer(t),frame(2,msg),frame(4,key),frame(2,s),frame(2,cert)});}
int main(int argc,char**argv){try{
 if(argc!=4)throw std::runtime_error("usage: asiaccs27_bench n r samples");
 const auto n=static_cast<std::uint32_t>(std::stoul(argv[1])),r=static_cast<std::uint32_t>(std::stoul(argv[2])),samples=static_cast<std::uint32_t>(std::stoul(argv[3]));
 auto d=dimensions(n,(2*n+2)/3);if(!d||r>d->kappa||!samples||samples>10000)throw std::runtime_error("bad parameters");
 const auto t=(2*n+2)/3;PublicBytes ctx{'b','e','n','c','h'},msg(32,0x42);
 Roster roster{{},{}};roster.public_keys.reserve(n);PublicBytes roster_points;
 std::vector<SecretScalar> secret_keys;secret_keys.reserve(n);
 for(std::uint32_t i=1;i<=n;++i){auto sk=random_secret_scalar();auto pk=public_generator_multiply(PublicBytes(sk.bytes().begin(),sk.bytes().end()));if(!pk)throw std::runtime_error("public key derivation failed");secret_keys.push_back(std::move(sk));roster.public_keys.push_back(*pk);auto f=frame(4,*pk);roster_points.insert(roster_points.end(),f.begin(),f.end());}
 auto rt=transcript("ROSTER",{frame_integer(n),frame(6,roster_points)});unsigned int digest_len=0;
 EVP_Digest(rt.data(),rt.size(),roster.digest.data(),&digest_len,EVP_sha256(),nullptr);if(digest_len!=roster.digest.size())throw std::runtime_error("roster digest failed");
 std::vector<std::uint64_t> subset;for(std::uint32_t i=1;i<=t;++i)subset.push_back(i);
 std::uint64_t sid=1;constexpr int warmups=10;
 for(int k=-warmups;k<static_cast<int>(samples);++k){PublicBytes id(8);for(int i=0;i<8;++i)id[7-i]=(sid>>(8*i))&255;
 auto tweak=random_secret_scalar();auto coordinator_tweak=SecretScalar::from_canonical(tweak.bytes());ProofTimings proof_times;
 auto coordinator_start=Clock::now();auto start=Clock::now();auto c=CoordinatorSession::begin(roster,id,t,msg,subset,std::move(coordinator_tweak),ctx,r,&proof_times);auto prove_ns=elapsed(start);if(!c)throw std::runtime_error("certificate generation failed");
 auto proof=decode_authorization_proof(c->certificate(),n,r);if(!proof)throw std::runtime_error("certificate decode failed");
 VerificationTimings certificate_times;start=Clock::now();if(!verify_authorization(roster,ctx,t,msg,c->masked_key(),*proof,r,&certificate_times))throw std::runtime_error("certificate verification failed");auto verify_ns=elapsed(start);
 std::map<std::uint64_t,RoundOneCommitments> commitments;std::vector<SecretScalar> nonce1,nonce2;nonce1.reserve(t);nonce2.reserve(t);
 for(std::uint32_t i=0;i<t;++i){nonce1.push_back(random_secret_scalar());nonce2.push_back(random_secret_scalar());commitments.emplace(i+1,RoundOneCommitments{secret_generator_multiply(nonce1.back()),secret_generator_multiply(nonce2.back())});}
 start=Clock::now();auto aggregate=c->collect_commitments(commitments);auto coordinator_nonce_aggregation_ns=elapsed(start);if(!aggregate)throw std::runtime_error("coordinator rejected commitments");
 const auto digest_bytes=PublicBytes(roster.digest.begin(),roster.digest.end());auto session_context=make_context(id,digest_bytes,t,msg,c->masked_key(),subset,c->certificate());
 const auto beta_array=scalar_challenge(transcript("NON",{frame(2,session_context),frame(4,aggregate->first),frame(4,aggregate->second)}),false);PublicBytes beta(beta_array.begin(),beta_array.end());
 auto weighted_R2=public_point_multiply(aggregate->second,beta);auto R=weighted_R2?public_point_add(aggregate->first,*weighted_R2):std::nullopt;if(!R)throw std::runtime_error("aggregate nonce invalid");
 const auto challenge_array=scalar_challenge(transcript("SIG",{frame(2,digest_bytes),frame(4,c->masked_key()),frame_integer(t),frame(4,*R),frame(2,msg),frame(2,c->certificate())}),false);auto challenge_secret=SecretScalar::from_canonical(challenge_array);
 std::map<std::uint64_t,PublicBytes> responses;
 for(std::uint32_t i=0;i<t;++i){auto nonce=secret_scalar_add(nonce1[i],secret_scalar_multiply(secret_from(beta),nonce2[i]));auto keyterm=secret_scalar_multiply(challenge_secret,secret_keys[i]);auto response=secret_scalar_add(nonce,keyterm);responses.emplace(i+1,PublicBytes(response.bytes().begin(),response.bytes().end()));}
 start=Clock::now();for(std::uint32_t i=1;i<=t;++i)if(!c->verify_partial_response(i,responses.at(i)))throw std::runtime_error("coordinator rejected a share");auto share_verification_ns=elapsed(start);
 start=Clock::now();auto schnorr=c->aggregate_responses(responses);auto coordinator_response_aggregation_ns=elapsed(start);if(!schnorr)throw std::runtime_error("coordinator response aggregation failed");
 const auto coordinator_total_ns=elapsed(coordinator_start);FinalSignature signature{*schnorr,*proof};
 VerificationTimings full_verify_times;start=Clock::now();if(!verify_signature(roster,ctx,t,msg,signature,r,&full_verify_times))throw std::runtime_error("full signature verification failed");auto full_verify_ns=elapsed(start);
 RoundOneRequest request{1,id,digest_bytes,t,msg,c->masked_key(),subset,c->certificate(),0,std::nullopt};
 auto request_bytes=encode_round_one_request(request);if(!request_bytes)throw std::runtime_error("Round-1 request encoding failed");
 Signer signer(1,SecretScalar::from_canonical(secret_keys[0].bytes()));SignerTimings signer_times;start=Clock::now();auto nonce=signer.round1(roster,id,t,msg,c->masked_key(),subset,ctx,c->certificate(),r,0,{},&signer_times);auto signer_ns=elapsed(start);if(!nonce)throw std::runtime_error("signer rejected certificate");
 auto r1wire=encode_round_one_response(RoundOneResponse{1,id,*nonce});if(!r1wire)throw std::runtime_error("Round-1 response encoding failed");
 PublicBytes mask(tweak.bytes().begin(),tweak.bytes().end());RoundOneRequest mode1_request{1,id,digest_bytes,t,msg,c->masked_key(),subset,c->certificate(),1,mask};auto mode1_request_bytes=encode_round_one_request(mode1_request);if(!mode1_request_bytes)throw std::runtime_error("mask-disclosure request encoding failed");
 Signer mode1_signer(1,SecretScalar::from_canonical(secret_keys[0].bytes()));SignerTimings mode1_times;start=Clock::now();auto mode1_nonce=mode1_signer.round1(roster,id,t,msg,c->masked_key(),subset,ctx,c->certificate(),r,1,mask,&mode1_times);auto mode1_signer_ns=elapsed(start);if(!mode1_nonce)throw std::runtime_error("mask-disclosure signer rejected certificate");
 auto mode1_r1wire=encode_round_one_response(RoundOneResponse{1,id,*mode1_nonce});if(!mode1_r1wire)throw std::runtime_error("mask-disclosure Round-1 response encoding failed");
 start=Clock::now();auto response=signer.round2(id,aggregate->first,aggregate->second);auto round2_ns=elapsed(start);if(!response)throw std::runtime_error("signer rejected Round-2 aggregate");
 start=Clock::now();auto mode1_response=mode1_signer.round2(id,aggregate->first,aggregate->second);auto mode1_round2_ns=elapsed(start);if(!mode1_response)throw std::runtime_error("mask-disclosure signer rejected Round-2 aggregate");
 auto r2request=encode_round_two_request(RoundTwoRequest{1,id,*aggregate});
 auto r2response=encode_round_two_response(RoundTwoResponse{1,id,*response});
 auto mode1_r2response=encode_round_two_response(RoundTwoResponse{1,id,*mode1_response});
 if(!r2request||!r2response||!mode1_r2response)throw std::runtime_error("Round-2 wire encoding failed");
 if(k>=0){auto bytes=encode_authorization_proof(*proof,n,r);auto sigbytes=encode_signature(signature,n,r);std::cout<<"{\"n\":"<<n<<",\"t\":"<<t<<",\"r\":"<<r<<",\"sample\":"<<k<<",\"prove_ns\":"<<prove_ns<<",\"proof_total_ns\":"<<proof_times.total_ns<<",\"commitments_ns\":"<<proof_times.commitments_ns<<",\"other_proof_ns\":"<<proof_times.other_proof_ns<<",\"fold_round_ns\":[";for(std::size_t j=0;j<proof_times.folding_round_ns.size();++j){if(j)std::cout<<",";std::cout<<proof_times.folding_round_ns[j];}std::cout<<"],\"nonce_aggregation_ns\":"<<coordinator_nonce_aggregation_ns<<",\"share_verification_ns\":"<<share_verification_ns<<",\"response_aggregation_ns\":"<<coordinator_response_aggregation_ns<<",\"serial_end_to_end_ns\":"<<coordinator_total_ns<<",\"certificate_verify_ns\":"<<verify_ns<<",\"verify_v1_ns\":"<<full_verify_times.v1_ns<<",\"verify_folding_scalars_ns\":"<<full_verify_times.folding_scalars_ns<<",\"verify_v2_msm_ns\":"<<full_verify_times.v2_msm_ns<<",\"verify_schnorr_equation_ns\":"<<full_verify_times.schnorr_equation_ns<<",\"full_verify_ns\":"<<full_verify_ns<<",\"signer_round1_ns\":"<<signer_ns<<",\"signer_cert_verify_ns\":"<<signer_times.certificate_verify_ns<<",\"signer_nonce_generation_ns\":"<<signer_times.nonce_generation_ns<<",\"signer_round2_ns\":"<<round2_ns<<",\"mode1_signer_round1_ns\":"<<mode1_signer_ns<<",\"mode1_cert_verify_ns\":"<<mode1_times.certificate_verify_ns<<",\"mode1_linkage_ns\":"<<mode1_times.mask_linkage_ns<<",\"mode1_nonce_generation_ns\":"<<mode1_times.nonce_generation_ns<<",\"mode1_signer_round2_ns\":"<<mode1_round2_ns<<",\"certificate_bytes\":"<<(bytes?bytes->size():0)<<",\"signature_bytes\":"<<(sigbytes?sigbytes->size():0)<<",\"round1_request_bytes\":"<<request_bytes->size()<<",\"mode1_round1_request_bytes\":"<<mode1_request_bytes->size()<<",\"round1_response_bytes\":"<<r1wire->size()<<",\"mode1_round1_response_bytes\":"<<mode1_r1wire->size()<<",\"round2_request_bytes\":"<<r2request->size()<<",\"round2_response_bytes\":"<<r2response->size()<<",\"mode1_round2_response_bytes\":"<<mode1_r2response->size()<<"}\n";}
 ++sid;
 }
 }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}return 0;}
