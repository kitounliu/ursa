use crate::errors::prelude::*;
use crate::keys::prelude::*;
use crate::pok_sig::prelude::*;
use crate::prelude::PoKOfCommitsProofStatus;
/// The verifier of a signature or credential asks for messages to be revealed from
/// a prover and checks the signature proof of knowledge against a trusted issuer's public key.
use crate::{
    GeneratorG1, HashElem, ProofChallenge, ProofNonce, ProofRequest, RandomElem,
    SignatureCommitsProof, SignatureMessage,
};
use std::collections::BTreeSet;

/// This struct represents an Verifier of signatures.
/// Provided are methods for generating a context to ask for revealed messages
/// and the prover keep all others hidden.
pub struct Verifier;

impl Verifier {
    /// Create a nonce used for the zero-knowledge proof context
    /// verkey: issuer's public key
    pub fn new_proof_request(
        revealed_message_indices: &[usize],
        committed_message_indices: &[usize],
        verkey: &PublicKey,
    ) -> Result<ProofRequest, BBSError> {
        let revealed_messages = revealed_message_indices
            .iter()
            .copied()
            .collect::<BTreeSet<usize>>();
        for i in &revealed_messages {
            if *i > verkey.h.len() {
                return Err(BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    *i,
                    verkey.h.len(),
                )
                .into());
            }
        }

        let committed_messages = committed_message_indices
            .iter()
            .copied()
            .collect::<BTreeSet<usize>>();
        for i in &committed_messages {
            if *i > verkey.h.len() {
                return Err(BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    *i,
                    verkey.h.len(),
                )
                .into());
            }
        }

        if !revealed_messages.is_disjoint(&committed_messages) {
            return Err(BBSErrorKind::GeneralError {
                msg: String::from("should not reveal committed messages"),
            }
            .into());
        }

        Ok(ProofRequest {
            revealed_messages,
            committed_messages,
            verification_key: verkey.clone(),
        })
    }

    /// Check a signature proof of knowledge and selective disclosure proof
    pub fn verify_signature_pok(
        proof_request: &ProofRequest,
        signature_proof: &SignatureCommitsProof,
        nonce: &ProofNonce,
    ) -> Result<Vec<SignatureMessage>, BBSError> {
        let mut challenge_bytes = signature_proof.proof.get_bytes_for_challenge(
            proof_request.revealed_messages.clone(),
            &proof_request.verification_key,
        );
        challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

        let challenge_verifier = ProofChallenge::hash(&challenge_bytes);
        match signature_proof.proof.verify(
            &proof_request.verification_key,
            &signature_proof.revealed_messages,
            &challenge_verifier,
        )? {
            PoKOfSignatureProofStatus::Success => Ok(signature_proof
                .revealed_messages
                .iter()
                .map(|(_, m)| *m)
                .collect::<Vec<SignatureMessage>>()),
            e => Err(BBSErrorKind::InvalidProof { status: e }.into()),
        }
    }

    /// Check a signature proof of knowledge and selective disclosure proof
    pub fn verify_signature_commits_pok(
        proof_request: &ProofRequest,
        signature_proof: &SignatureCommitsProof,
        nonce: &ProofNonce,
        g: &GeneratorG1,
        h: &GeneratorG1,
    ) -> Result<Vec<SignatureMessage>, BBSError> {
        if proof_request.committed_messages.is_empty() || signature_proof.commits_proof.is_none() {
            return Verifier::verify_signature_pok(proof_request, signature_proof, nonce);
        }
        let pok_commits = signature_proof.commits_proof.as_ref().expect("cannot fail");

        let mut challenge_bytes = signature_proof.proof.get_bytes_for_challenge(
            proof_request.revealed_messages.clone(),
            &proof_request.verification_key,
        );
        challenge_bytes.extend(&pok_commits.get_bytes_for_challenge(&g, &h));
        challenge_bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);

        let challenge_verifier = ProofChallenge::hash(&challenge_bytes);

        let proof_status = signature_proof.proof.verify(
            &proof_request.verification_key,
            &signature_proof.revealed_messages,
            &challenge_verifier,
        )?;

        if proof_status != PoKOfSignatureProofStatus::Success {
            return Err(BBSErrorKind::InvalidProof {
                status: proof_status,
            }
            .into());
        }

        let proof_commits_status = pok_commits.verify(&challenge_verifier, &g, &h)?;
        if proof_commits_status != PoKOfCommitsProofStatus::Success {
            return Err(BBSErrorKind::InvalidProofCommits {
                status: proof_commits_status,
            }
            .into());
        }

        // check the linked responses for committed messages
        let total = (0..proof_request.verification_key.h.len()).collect::<BTreeSet<usize>>();
        let non_revealed: Vec<_> = total
            .difference(&proof_request.revealed_messages)
            .cloned()
            .collect();
        let mut committed: Vec<_> = proof_request.committed_messages.iter().cloned().collect();
        committed.sort();

        // find the positions of the committed messages in pok of signature
        let mut pos = Vec::new();
        for c in committed.iter() {
            let i = non_revealed
                .iter()
                .position(|x| *x == *c)
                .expect("cannot fail");
            pos.push(i);
        }

        for (i, p) in pos.iter().enumerate() {
            let z_sig = signature_proof.proof.get_resp_for_message(*p).unwrap();
            let z_commits = pok_commits.get_resp_for_message(i).unwrap();
            if !z_sig.eq(&z_commits) {
                return Err(BBSErrorKind::GeneralError {
                    msg: String::from("responses for committed messages do not match"),
                }
                .into());
            }
        }

        Ok(signature_proof
            .revealed_messages
            .iter()
            .map(|(_, m)| *m)
            .collect::<Vec<SignatureMessage>>())
    }

    /// Create a nonce used for the proof request context
    pub fn generate_proof_nonce() -> ProofNonce {
        ProofNonce::random()
    }

    /// create the challenge hash for a set of proofs
    ///
    /// # Arguments
    /// * `proofs` - a slice of SignatureCommitsProof objects
    /// * `proof_requests` - a corresponding slice of ProofRequest objects
    /// * `nonce` - a SignatureNonce
    /// * `claims` - an optional slice of bytes the prover wishes to include in the challenge
    pub fn create_challenge_hash(
        proofs: &[SignatureCommitsProof],
        proof_requests: &[ProofRequest],
        nonce: &ProofNonce,
        claims: Option<&[&[u8]]>,
    ) -> Result<ProofChallenge, BBSError> {
        let mut bytes = Vec::new();

        let mut commits = Vec::new();
        for pr in proofs.iter().zip(proof_requests.iter()) {
            let (p, r) = pr;
            bytes.extend_from_slice(
                p.proof
                    .get_bytes_for_challenge(r.revealed_messages.clone(), &r.verification_key)
                    .as_slice(),
            );
            if let Some(pc) = &p.commits_proof {
                commits.push(pc.to_bytes(false));
            }
        }

        for c in commits.iter() {
            bytes.extend_from_slice(c.as_slice());
        }

        bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
        if let Some(claim) = claims {
            for c in claim {
                bytes.extend_from_slice(c);
            }
        }
        let challenge = ProofChallenge::hash(&bytes);
        Ok(challenge)
    }
}
