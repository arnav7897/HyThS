use frost_secp256k1 as frost;
use std::{collections::BTreeMap, env, time::Instant};

fn main() {
    let n: u16 = env::args().nth(1).expect("n").parse().expect("integer n");
    let t = (n / 2).max(2);
    assert!(n >= 2 && t <= n);
    let mut rng = rand_core::UnwrapErr(rand::rngs::SysRng);
    let start = Instant::now();
    let (shares, public) = frost::keys::generate_with_dealer(
        n, t, frost::keys::IdentifierList::Default, &mut rng,
    ).unwrap();
    let dealer_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let keys: BTreeMap<_, frost::keys::KeyPackage> = shares.into_iter().map(|(id, share)| {
        (id, frost::keys::KeyPackage::try_from(share).unwrap())
    }).collect();
    let key_validation_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key) in keys.iter().take(t as usize) {
        let (nonce, commitment) = frost::round1::commit(key.signing_share(), &mut rng);
        nonces.insert(*id, nonce);
        commitments.insert(*id, commitment);
    }
    let round1_ns = start.elapsed().as_nanos();
    let message = b"hta-frost-comparison";
    let package = frost::SigningPackage::new(commitments, message);
    let start = Instant::now();
    let mut responses = BTreeMap::new();
    for (id, nonce) in &nonces {
        responses.insert(*id, frost::round2::sign(&package, nonce, &keys[id]).unwrap());
    }
    let round2_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let signature = frost::aggregate(&package, &responses, &public).unwrap();
    let aggregate_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    public.verifying_key().verify(message, &signature).unwrap();
    let verify_ns = start.elapsed().as_nanos();
    assert!(public.verifying_key().verify(b"wrong message", &signature).is_err());
    let bytes = signature.serialize().unwrap();
    assert_eq!(signature, frost::Signature::deserialize(&bytes).unwrap());
    println!("{{\"n\":{n},\"t\":{t},\"k\":{t},\"dealer_ns\":{dealer_ns},\"key_validation_ns\":{key_validation_ns},\"round1_ns\":{round1_ns},\"round2_ns\":{round2_ns},\"aggregate_ns\":{aggregate_ns},\"verify_ns\":{verify_ns},\"signature_bytes\":{}}}", bytes.len());
}
