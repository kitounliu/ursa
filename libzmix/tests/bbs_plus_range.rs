extern crate amcl_wrapper;
extern crate bbs;
extern crate bulletproofs_amcl;
extern crate ff_zeroize;
extern crate merlin;
extern crate pairing_plus;
extern crate rand;

use ff_zeroize::PrimeField;
use pairing_plus::bls12_381::Fr;

use bbs::prelude::*;
use bbs::{pm_committed, pm_committed_raw, pm_hidden, pm_hidden_raw, pm_revealed, pm_revealed_raw};

use amcl_wrapper::field_elem::FieldElement as AMCL_Fr;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::{G1Vector as AMCL_G1Vector, G1 as AMCL_G1};

use bulletproofs_amcl::r1cs::gadgets::bound_check::{
    prove_bounded_num as bullet_prove_bounded_num, verify_bounded_num as bullet_verify_bounded_num,
};
use bulletproofs_amcl::r1cs::{Prover as Bullet_Prover, Verifier as Bullet_Verifier};
use bulletproofs_amcl::utils::get_generators as bullet_get_generators;

use merlin::Transcript;

use rand::thread_rng;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::io::Cursor;

#[test]
fn bbs_plus_range_raw() {
    let mut rng = rand::thread_rng();
    let (pk, sk) = Issuer::new_keys(2).unwrap();

    // nonce from verifier
    let nonce = ProofNonce::random();

    let age: Fr = Fr::from_str("30").unwrap();
    let age_mess = SignatureMessage::from(age.clone());
    let messages = vec![SignatureMessage::hash(b"alice"), age_mess];
    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    // hash("g") and hash("h") consistent with the one in amcl
    let amcl_g = AMCL_G1::from_msg_hash("g".as_bytes());
    let g_bytes = amcl_g1_to_pp_bytes_uncompressed(&amcl_g);
    let g = GeneratorG1::try_from(&g_bytes[..]).unwrap();

    let amcl_h = AMCL_G1::from_msg_hash("h".as_bytes());
    let h_bytes = amcl_g1_to_pp_bytes_uncompressed(&amcl_h);
    let h = GeneratorG1::try_from(&h_bytes[..]).unwrap();

    let rho_age = ProofNonce::random();

    // Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![pm_hidden!(b"alice"), pm_committed_raw!(age_mess, rho_age)];

    let pok_sig = PoKOfSignature::init(&signature, &pk, proof_messages.as_slice()).unwrap();
    let pok_commits = PoKOfCommits::init(&proof_messages, &g, &h).unwrap();

    let mut bytes = Vec::new();
    bytes.extend(&nonce.to_bytes_uncompressed_form());
    bytes.extend(pok_sig.to_bytes());
    bytes.extend(pok_commits.to_bytes());

    let challenge_prover = ProofChallenge::hash(&bytes);
    let pok_sig_proof = pok_sig.gen_proof(&challenge_prover).unwrap();

    // save secrets and commit for creating range proof for age
    // age is the second message but it is the first message that is committed
    let secrets = pok_commits.get_secrets_for_message(0).unwrap();
    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0], age);
    let commit = pok_commits.get_commit_for_message(0).unwrap();

    // convert secrets and commit into AMCL format
    let amcl_secrets: Vec<AMCL_Fr> = secrets
        .iter()
        .map(|s| {
            let s_bytes = pp_fr_to_amcl_fr_bytes(&s);
            AMCL_Fr::from_bytes(&s_bytes).unwrap()
        })
        .collect();
    let amcl_commit_bytes = pp_g1_uncompressed_to_amcl_g1_bytes(&commit);
    let amcl_commit = AMCL_G1::from_bytes(&amcl_commit_bytes).unwrap();

    // create zkp for commitments
    let pok_commits_proof = pok_commits.gen_proof(&challenge_prover).unwrap();

    // create range proof
    let min = 25;
    let max = 75;
    let max_bits_in_val = 32;
    let big_g: AMCL_G1Vector = bullet_get_generators("G", 512).into();
    let big_h: AMCL_G1Vector = bullet_get_generators("H", 512).into();

    let transcript_label = b"BoundChecks";
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut bullet_prover = Bullet_Prover::new(&amcl_g, &amcl_h, &mut prover_transcript);

    let comms = bullet_prove_bounded_num(
        30,
        Some(amcl_secrets[1].clone()),
        min,
        max,
        max_bits_in_val,
        Some(&mut rng),
        &mut bullet_prover,
    )
    .unwrap();

    let bullet_proof = bullet_prover.prove(&big_g, &big_h).unwrap();

    // The final proofs are (pok_sig_proof, pok_commits_proof, comms, bullet_proof)

    // verify sig and commits proofs
    let mut bytes = Vec::new();
    bytes.extend(&nonce.to_bytes_compressed_form());
    let psb = pok_sig_proof.get_bytes_for_challenge(BTreeSet::new(), &pk);
    bytes.extend(&psb);
    let pcb = pok_commits_proof.get_bytes_for_challenge(&g, &h);
    bytes.extend(&pcb);

    let challenge_verifier = ProofChallenge::hash(&bytes);

    assert_eq!(challenge_prover, challenge_verifier);

    let result_sig = pok_sig_proof
        .verify(&pk, &BTreeMap::new(), &challenge_verifier)
        .unwrap();
    assert_eq!(result_sig, PoKOfSignatureProofStatus::Success);
    let result_commits = pok_commits_proof
        .verify(&challenge_verifier, &g, &h)
        .unwrap();
    assert_eq!(result_commits, PoKOfCommitsProofStatus::Success);

    let z_age_sig = pok_sig_proof.get_resp_for_message(1).unwrap();
    let z_age_commits = pok_commits_proof.get_resp_for_message(0).unwrap();
    assert_eq!(z_age_sig, z_age_commits);

    // verify commitment consistence
    assert_eq!(amcl_commit, comms[0]);

    // verify bullet proof
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut bullet_verifier = Bullet_Verifier::new(&mut verifier_transcript);

    bullet_verify_bounded_num(min, max, max_bits_in_val, comms, &mut bullet_verifier).unwrap();
    assert!(bullet_verifier
        .verify(&bullet_proof, &amcl_g, &amcl_h, &big_g, &big_h)
        .is_ok());
}

#[test]
fn bbs_plus_range() {
    let mut rng = rand::thread_rng();
    let (pk, sk) = Issuer::new_keys(2).unwrap();

    let age: Fr = Fr::from_str("30").unwrap();
    let age_mess = SignatureMessage::from(age.clone());
    let messages = vec![SignatureMessage::hash(b"alice"), age_mess];
    let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();

    // hash("g") and hash("h") used in bulletproof_amcl
    let amcl_g = AMCL_G1::from_msg_hash("g".as_bytes());
    let g_bytes = amcl_g1_to_pp_bytes_uncompressed(&amcl_g);
    let g = GeneratorG1::try_from(&g_bytes[..]).unwrap();

    let amcl_h = AMCL_G1::from_msg_hash("h".as_bytes());
    let h_bytes = amcl_g1_to_pp_bytes_uncompressed(&amcl_h);
    let h = GeneratorG1::try_from(&h_bytes[..]).unwrap();

    // nonce and proof_request from verifier
    let nonce = Verifier::generate_proof_nonce();
    let proof_request = Verifier::new_proof_request(&[], &[1], &pk).unwrap();

    // linked blinding
    let rho_age = ProofNonce::random();

    // Sends `proof_request` and `nonce` to the prover
    let proof_messages = vec![pm_hidden!(b"alice"), pm_committed_raw!(age_mess, rho_age)];

    let (pok_sig, pok_commits) =
        Prover::commit_signature_commits_pok(&proof_request, &proof_messages, &signature, &g, &h)
            .unwrap();

    let challenge = Prover::create_challenge_hash(
        &[pok_sig.clone()],
        Some(&[pok_commits.clone()]),
        None,
        &nonce,
    )
    .unwrap();

    // save secrets and commit for creating range proof for age
    // age is the second message but it is the first message that is committed
    let secrets = pok_commits.get_secrets_for_message(0).unwrap();
    assert_eq!(secrets.len(), 2);
    assert_eq!(secrets[0], age);
    let commit = pok_commits.get_commit_for_message(0).unwrap();

    // convert secrets and commit into AMCL format
    let amcl_secrets: Vec<AMCL_Fr> = secrets
        .iter()
        .map(|s| {
            let s_bytes = pp_fr_to_amcl_fr_bytes(&s);
            AMCL_Fr::from_bytes(&s_bytes).unwrap()
        })
        .collect();
    let amcl_commit_bytes = pp_g1_uncompressed_to_amcl_g1_bytes(&commit);
    let amcl_commit = AMCL_G1::from_bytes(&amcl_commit_bytes).unwrap();

    // create pok for signature and commitments
    let proof = Prover::generate_signature_commits_pok(pok_sig, pok_commits, &challenge).unwrap();

    // create range proof
    let min = 25;
    let max = 75;
    let max_bits_in_val = 32;
    let big_g: AMCL_G1Vector = bullet_get_generators("G", 512).into();
    let big_h: AMCL_G1Vector = bullet_get_generators("H", 512).into();

    let transcript_label = b"BoundChecks";
    let mut prover_transcript = Transcript::new(transcript_label);
    let mut bullet_prover = Bullet_Prover::new(&amcl_g, &amcl_h, &mut prover_transcript);

    let comms = bullet_prove_bounded_num(
        30,
        Some(amcl_secrets[1].clone()),
        min,
        max,
        max_bits_in_val,
        Some(&mut rng),
        &mut bullet_prover,
    )
    .unwrap();

    let bullet_proof = bullet_prover.prove(&big_g, &big_h).unwrap();

    // The final proofs are (pok_sig_proof, pok_commits_proof, comms, bullet_proof)

    // verify sig and commits proofs
    Verifier::verify_signature_commits_pok(&proof_request, &proof, &nonce, &g, &h).unwrap();

    // verify commitment consistence
    assert_eq!(amcl_commit, comms[0]);

    // verify bullet proof
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut bullet_verifier = Bullet_Verifier::new(&mut verifier_transcript);

    bullet_verify_bounded_num(
        min,
        max,
        max_bits_in_val,
        comms.clone(),
        &mut bullet_verifier,
    )
    .unwrap();
    assert!(bullet_verifier
        .verify(&bullet_proof, &amcl_g, &amcl_h, &big_g, &big_h)
        .is_ok());

    // test wrong scope
    let mut verifier_transcript = Transcript::new(transcript_label);
    let mut bullet_verifier = Bullet_Verifier::new(&mut verifier_transcript);
    bullet_verify_bounded_num(40, max, max_bits_in_val, comms, &mut bullet_verifier).unwrap();
    assert!(bullet_verifier
        .verify(&bullet_proof, &amcl_g, &amcl_h, &big_g, &big_h)
        .is_err());
}
