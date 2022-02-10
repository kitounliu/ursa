use crate::errors::prelude::*;
use crate::keys::prelude::*;
use crate::messages::*;
use crate::pok_commit::prelude::*;
use crate::pok_sig::prelude::*;
use crate::pok_vc::prelude::*;
use crate::signature::prelude::*;
/// The prover of a signature or credential receives it from an
/// issuer and later proves to a verifier.
/// The prover can either have the issuer sign all messages
/// or can have some (0 to all) messages blindly signed by the issuer.
use crate::{
    BlindSignatureContext, CommitmentBuilder, GeneratorG1, HashElem, ProofChallenge, ProofNonce,
    ProofRequest, RandomElem, SignatureBlinding, SignatureCommitsProof, SignatureMessage,
};
use std::collections::{BTreeMap, BTreeSet};

/// This struct represents a Prover who receives signatures or proves with them.
/// Provided are methods for 2PC where some are only known to the prover and a blind signature
/// is created, unblinding signatures, verifying signatures, and creating signature proofs of knowledge
/// with selective disclosure proofs
pub struct Prover {}

impl Prover {
    /// Generate a unique message that will be used across multiple signatures.
    /// This `link_secret` is the same in all signatures and allows a prover to demonstrate
    /// that signatures were issued to the same identity. This value should be a blinded
    /// message in all signatures and never revealed to anyone.
    pub fn new_link_secret() -> SignatureMessage {
        SignatureMessage::random()
    }

    /// Create the structures need to send to an issuer to complete a blinded signature
    pub fn new_blind_signature_context(
        verkey: &PublicKey,
        messages: &BTreeMap<usize, SignatureMessage>,
        nonce: &ProofNonce,
    ) -> Result<(BlindSignatureContext, SignatureBlinding), BBSError> {
        let blinding_factor = Signature::generate_blinding();
        let mut builder = CommitmentBuilder::new();

        // h0^blinding_factor*hi^mi.....
        builder.add(&verkey.h0, &blinding_factor);

        let mut committing = ProverCommittingG1::new();
        committing.commit(&verkey.h0);
        let mut secrets = Vec::new();
        secrets.push(SignatureMessage(blinding_factor.0));
        for (i, m) in messages {
            if *i > verkey.h.len() {
                return Err(BBSErrorKind::PublicKeyGeneratorMessageCountMismatch(
                    *i,
                    verkey.h.len(),
                )
                .into());
            }
            secrets.push(*m);
            builder.add(&verkey.h[*i], &m);
            committing.commit(&verkey.h[*i]);
        }

        // Create a random commitment, compute challenges and response.
        // The proof of knowledge consists of a commitment and responses
        // Prover and issuer engage in a proof of knowledge for `commitment`
        let commitment = builder.finalize();
        let committed = committing.finish();

        let mut extra = Vec::new();
        extra.extend_from_slice(&commitment.to_bytes_uncompressed_form()[..]);
        extra.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
        let challenge_hash = committed.gen_challenge(extra);
        let proof_of_hidden_messages = committed
            .gen_proof(&challenge_hash, secrets.as_slice())
            .unwrap();

        Ok((
            BlindSignatureContext {
                challenge_hash,
                commitment,
                proof_of_hidden_messages,
            },
            blinding_factor,
        ))
    }

    /// Unblinds and verifies a signature received from an issuer
    pub fn complete_signature(
        verkey: &PublicKey,
        messages: &[SignatureMessage],
        blind_signature: &BlindSignature,
        blinding_factor: &SignatureBlinding,
    ) -> Result<Signature, BBSError> {
        let signature = blind_signature.to_unblinded(blinding_factor);
        if signature.verify(messages, verkey)? {
            Ok(signature)
        } else {
            Err(BBSErrorKind::GeneralError {
                msg: "Invalid signature.".to_string(),
            }
            .into())
        }
    }

    /// Create a new signature proof of knowledge and selective disclosure proof
    /// from a verifier's request
    ///
    /// # Arguments
    /// * `request` - Proof request from verifier
    /// * `proof_messages` -
    /// If blinding_factor is Some(Nonce) then it will use that.
    /// If None, a blinding factor will be generated at random.
    pub fn commit_signature_pok(
        request: &ProofRequest,
        proof_messages: &[ProofMessage],
        signature: &Signature,
    ) -> Result<PoKOfSignature, BBSError> {
        PoKOfSignature::init(&signature, &request.verification_key, proof_messages)
    }

    /// Create a new proof of knowledge for signature with commits and selective disclosure proof
    /// from a verifier's request
    ///
    /// # Arguments
    /// * `request` - Proof request from verifier
    /// * `proof_messages` -
    /// If blinding_factor is Some(Nonce) then it will use that.
    /// If None, a blinding factor will be generated at random.
    pub fn commit_signature_commits_pok(
        request: &ProofRequest,
        proof_messages: &[ProofMessage],
        signature: &Signature,
        g: &GeneratorG1,
        h: &GeneratorG1,
    ) -> Result<(PoKOfSignature, PoKOfCommits), BBSError> {
        let pok_sig = PoKOfSignature::init(&signature, &request.verification_key, proof_messages)?;
        let pok_commits = PoKOfCommits::init(&proof_messages, &g, &h)?;
        Ok((pok_sig, pok_commits))
    }

    /// Create the challenge hash for a set of proofs
    ///
    /// # Arguments
    /// * `poks` - a vec of PoKOfSignature objects
    /// * `nonce` - a SignatureNonce
    /// * `claims` - an optional slice of bytes the prover wishes to include in the challenge
    pub fn create_challenge_hash(
        pok_sigs: &[PoKOfSignature],
        pok_commits: Option<&[PoKOfCommits]>,
        claims: Option<&[&[u8]]>,
        nonce: &ProofNonce,
    ) -> Result<ProofChallenge, BBSError> {
        let mut bytes = Vec::new();

        for p in pok_sigs {
            bytes.extend_from_slice(p.to_bytes().as_slice());
        }

        if let Some(commits) = pok_commits {
            for c in commits.iter() {
                bytes.extend_from_slice(c.to_bytes().as_slice());
            }
        }

        bytes.extend_from_slice(&nonce.to_bytes_uncompressed_form()[..]);
        if let Some(add_claims) = claims {
            for c in add_claims {
                bytes.extend_from_slice(c);
            }
        }

        let challenge = ProofChallenge::hash(&bytes);
        Ok(challenge)
    }

    /// Convert the a committed proof of signature knowledge to the proof
    pub fn generate_signature_pok(
        pok_sig: PoKOfSignature,
        challenge: &ProofChallenge,
    ) -> Result<SignatureCommitsProof, BBSError> {
        let revealed_messages = pok_sig.revealed_messages.clone();
        let proof = pok_sig.gen_proof(challenge)?;

        Ok(SignatureCommitsProof {
            revealed_messages,
            proof,
            committed_messages: BTreeSet::default(),
            commits_proof: None,
        })
    }

    /// Convert the a committed proof of signature and commits to the proof
    pub fn generate_signature_commits_pok(
        pok_sig: PoKOfSignature,
        pok_commits: PoKOfCommits,
        challenge: &ProofChallenge,
    ) -> Result<SignatureCommitsProof, BBSError> {
        let revealed_messages = pok_sig.revealed_messages.clone();
        let proof = pok_sig.gen_proof(challenge)?;

        let committed_messages = pok_commits.committed_messages.clone();
        let tmp = pok_commits.gen_proof(&challenge)?;
        let mut commits_proof = None;
        if !tmp.commits.is_empty() {
            commits_proof = Some(tmp);
        }

        Ok(SignatureCommitsProof {
            revealed_messages,
            proof,
            committed_messages,
            commits_proof,
        })
    }
}
