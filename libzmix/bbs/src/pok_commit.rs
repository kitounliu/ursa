use crate::errors::prelude::*;

use crate::messages::*;
use crate::pok_vc::prelude::*;

use crate::{
    multi_scalar_mul_const_time_g1, rand_non_zero_fr, Commitment, GeneratorG1, ProofChallenge,
    SignatureMessage, ToVariableLengthBytes, G1_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE,
};

use pairing_plus::bls12_381::{Fr, G1};
use pairing_plus::serdes::SerDes;

use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{Cursor, Read};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Convenience importing module
pub mod prelude {
    pub use super::{PoKOfCommits, PoKOfCommitsProof, PoKOfCommitsProofStatus};
}

/// Proof of Knowledge of a Signature that is used by the prover
/// to construct `PoKOfSignatureProof`.
///
/// XXX: An optimization would be to combine the 2 relations into one by using the same techniques as Bulletproofs
#[derive(Debug, Clone)]
pub struct PoKOfCommits {
    /// Commitments for selected hidden messages
    commits: Vec<G1>,
    secrets: Vec<Vec<Fr>>,
    commits_proofs: Vec<ProverCommittedG1>,
    pub(crate) committed_messages: BTreeSet<usize>,
}

/// Indicates the status returned from `PoKOfSignatureProof`
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PoKOfCommitsProofStatus {
    /// The proof verified
    Success,
    /// The proof failed because the signature proof of knowledge failed
    BadCommit,
    /// The proof failed because a hidden message was invalid when the proof was created
    BadCommittedMessage,
}

impl PoKOfCommitsProofStatus {
    /// Return whether the proof succeeded or not
    pub fn is_valid(self) -> bool {
        matches!(self, PoKOfCommitsProofStatus::Success)
    }
}

impl Display for PoKOfCommitsProofStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match *self {
            PoKOfCommitsProofStatus::Success => write!(f, "Success"),
            PoKOfCommitsProofStatus::BadCommittedMessage => write!(
                f,
                "a message was supplied when the proof was created that was not signed or a message was revealed that was initially hidden"
            ),
            PoKOfCommitsProofStatus::BadCommit=> {
                write!(f, "An invalid signature was supplied")
            }
        }
    }
}

/// The actual proof that is sent from prover to verifier.
///
/// Contains the proof of 2 discrete log relations.
#[derive(Debug, Clone)]
pub struct PoKOfCommitsProof {
    pub(crate) commits: Vec<G1>,
    pub(crate) commits_proofs: Vec<ProofG1>,
}

impl PoKOfCommits {
    /// Creates the initial proof data before a Fiat-Shamir calculation
    pub fn init(
        messages: &[ProofMessage],
        g: &GeneratorG1,
        h: &GeneratorG1,
    ) -> Result<Self, BBSError> {
        let mut commits = Vec::new();
        let mut secrets = Vec::new();
        let mut proofs = Vec::new();
        let bases: Vec<G1> = vec![g.0.clone(), h.0.clone()];

        let mut committed_messages = BTreeSet::new();
        for i in 0..messages.len() {
            match &messages[i] {
                ProofMessage::Committed(HiddenMessage::ProofSpecificBlinding(m)) => {
                    let m_blinding = rand_non_zero_fr();
                    let scalars = vec![m.0, m_blinding];
                    let c = multi_scalar_mul_const_time_g1(&bases, &scalars);
                    commits.push(c);

                    secrets.push(scalars);

                    let mut pc = ProverCommittingG1::new();
                    pc.commit(g);
                    pc.commit(h);
                    let pf = pc.finish();
                    proofs.push(pf);
                    committed_messages.insert(i);
                }
                ProofMessage::Committed(HiddenMessage::ExternalBlinding(m, b)) => {
                    let m_blinding = rand_non_zero_fr();
                    let scalars = vec![m.0, m_blinding];
                    let c = multi_scalar_mul_const_time_g1(&bases, &scalars);
                    commits.push(c);

                    secrets.push(scalars);

                    let mut pc = ProverCommittingG1::new();
                    pc.commit_with(g, &b);
                    pc.commit(h);
                    let pf = pc.finish();
                    proofs.push(pf);
                    committed_messages.insert(i);
                }
                _ => {}
            }
        }

        Ok(Self {
            commits,
            secrets,
            commits_proofs: proofs,
            committed_messages,
        })
    }

    /// Return byte representation of public elements so they can be used for challenge computation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        for c in self.commits.iter() {
            c.serialize(&mut bytes, false)
                .expect("unable to serialize commits");
        }

        for p in self.commits_proofs.iter() {
            bytes.extend(p.to_bytes());
        }

        bytes
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    pub fn gen_proof(self, challenge_hash: &ProofChallenge) -> Result<PoKOfCommitsProof, BBSError> {
        let mut commits_proofs = Vec::new();
        if self.secrets.len() != self.commits_proofs.len() {
            return Err(
                PoKVCError::from_kind(PoKVCErrorKind::UnequalNoOfBasesExponents {
                    bases: self.commits_proofs.len(),
                    exponents: self.secrets.len(),
                })
                .into(),
            );
        }
        for (ss, p) in self.secrets.iter().zip(self.commits_proofs.iter()) {
            let s: Vec<_> = ss.iter().map(|x| SignatureMessage(*x)).collect();
            let pf = p.clone().gen_proof(challenge_hash, &s)?;
            commits_proofs.push(pf);
        }

        Ok(PoKOfCommitsProof {
            commits: self.commits,
            commits_proofs,
        })
    }

    /// Get secrets (message, message blinding) for i-th message to be used for external proofs
    pub fn get_secrets_for_message(&self, msg_idx: usize) -> Result<Vec<Fr>, BBSError> {
        if msg_idx >= self.secrets.len() {
            return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                msg: format!(
                    "Message index was given {} but should be less than {}",
                    msg_idx,
                    self.secrets.len()
                ),
            }));
        }

        Ok(self.secrets[msg_idx].clone())
    }

    /// Get commitment for i-th message to be used for external proofs
    pub fn get_commit_for_message(&self, msg_idx: usize) -> Result<G1, BBSError> {
        if msg_idx >= self.commits.len() {
            return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                msg: format!(
                    "Message index was given {} but should be less than {}",
                    msg_idx,
                    self.commits.len()
                ),
            }));
        }

        Ok(self.commits[msg_idx].clone())
    }
}

impl PoKOfCommitsProof {
    /// Return bytes that need to be hashed for generating challenge. Takes `self.a_bar`,
    /// `self.a_prime` and `self.d` and commitment and instance data of the two proof of knowledge protocols.
    pub fn get_bytes_for_challenge(&self, g: &GeneratorG1, h: &GeneratorG1) -> Vec<u8> {
        let mut bytes = vec![];

        for c in self.commits.iter() {
            c.serialize(&mut bytes, false)
                .expect("unable to serialize commits");
        }

        let mut g_bytes = vec![];
        g.0.serialize(&mut g_bytes, false)
            .expect("unable to serialize g");
        let mut h_bytes = vec![];
        h.0.serialize(&mut h_bytes, false)
            .expect("unable to serialize h");

        for p in self.commits_proofs.iter() {
            bytes.extend_from_slice(&g_bytes);
            bytes.extend_from_slice(&h_bytes);
            p.commitment.serialize(&mut bytes, false).unwrap();
        }

        bytes
    }

    /// Get the response from post-challenge phase of the Sigma protocol for the given message index `msg_idx`.
    /// Used when comparing message equality
    pub fn get_resp_for_message(&self, msg_idx: usize) -> Result<SignatureMessage, BBSError> {
        // 2 elements in self.proof_vc_2.responses are reserved for `&signature.e` and `r2`
        if msg_idx >= self.commits_proofs.len() {
            return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                msg: format!(
                    "Message index was given {} but should be less than {}",
                    msg_idx,
                    self.commits_proofs.len()
                ),
            }));
        }
        // 2 added to the index, since 0th and 1st index are reserved for `&signature.e` and `r2`
        Ok(SignatureMessage(self.commits_proofs[msg_idx].responses[0]))
    }

    /// Validate the proof
    pub fn verify(
        &self,
        challenge: &ProofChallenge,
        g: &GeneratorG1,
        h: &GeneratorG1,
    ) -> Result<PoKOfCommitsProofStatus, BBSError> {
        if self.commits.len() != self.commits_proofs.len() {
            return Err(BBSError::from_kind(BBSErrorKind::GeneralError {
                msg: format!(
                    "Unequal amount of commits ({}) and proofs ({})",
                    self.commits.len(),
                    self.commits_proofs.len()
                ),
            }));
        }

        let gh = vec![g.clone(), h.clone()];
        for (c, p) in self.commits.iter().zip(self.commits_proofs.iter()) {
            if !p.verify(&gh, &Commitment(*c), challenge)? {
                return Ok(PoKOfCommitsProofStatus::BadCommittedMessage);
            }
        }

        Ok(PoKOfCommitsProofStatus::Success)
    }

    /// Convert the proof to raw bytes
    pub(crate) fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut output = Vec::new();

        let commits_num: u32 = self.commits.len() as u32;
        output.extend_from_slice(&commits_num.to_be_bytes()[..]);
        for c in self.commits.iter() {
            c.serialize(&mut output, compressed)
                .expect("unable to serialize commits");
        }

        let commits_proofs_num: u32 = self.commits_proofs.len() as u32;
        output.extend_from_slice(&commits_proofs_num.to_be_bytes()[..]);
        for p in self.commits_proofs.iter() {
            let p_bytes = p.to_bytes(compressed);
            let p_len: u32 = p_bytes.len() as u32;
            output.extend_from_slice(&p_len.to_be_bytes()[..]);
            output.extend(&p_bytes);
        }
        output
    }

    /// Convert the byte slice into a proof
    pub(crate) fn from_bytes(
        data: &[u8],
        g1_size: usize,
        compressed: bool,
    ) -> Result<Self, BBSError> {
        if data.len() < g1_size * 2 {
            return Err(BBSError::from_kind(BBSErrorKind::PoKVCError {
                msg: format!("Invalid proof bytes. Expected at least {}", g1_size * 2),
            }));
        }
        let mut c = Cursor::new(data);

        let mut length_bytes = [0u8; 4];
        c.read_exact(&mut length_bytes).unwrap();
        let commits_num = u32::from_be_bytes(length_bytes) as usize;

        let mut commits = Vec::with_capacity(commits_num);
        for _ in 0..commits_num {
            let c = slice_to_elem!(&mut c, G1, compressed)?;
            commits.push(c);
        }

        let mut length_bytes = [0u8; 4];
        c.read_exact(&mut length_bytes).unwrap();
        let commits_proofs_num = u32::from_be_bytes(length_bytes) as usize;

        let mut offset = 8 + commits_proofs_num * g1_size;
        let mut end;
        let mut commits_proofs = Vec::with_capacity(commits_proofs_num);
        for _ in 0..commits_proofs_num {
            let proof_len = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
            offset = offset + 4;
            end = offset + proof_len;
            let p = ProofG1::from_bytes(&data[offset..end], g1_size, compressed)?;
            commits_proofs.push(p);
            offset = end;
        }

        Ok(Self {
            commits,
            commits_proofs,
        })
    }
}

impl ToVariableLengthBytes for PoKOfCommitsProof {
    type Output = PoKOfCommitsProof;
    type Error = BBSError;

    /// Convert the proof to a compressed raw bytes form.
    fn to_bytes_compressed_form(&self) -> Vec<u8> {
        self.to_bytes(true)
    }

    /// Convert compressed byte slice into a proof
    fn from_bytes_compressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self, BBSError> {
        Self::from_bytes(data.as_ref(), G1_COMPRESSED_SIZE, true)
    }

    fn to_bytes_uncompressed_form(&self) -> Vec<u8> {
        self.to_bytes(false)
    }

    fn from_bytes_uncompressed_form<I: AsRef<[u8]>>(data: I) -> Result<Self::Output, Self::Error> {
        Self::from_bytes(data.as_ref(), G1_UNCOMPRESSED_SIZE, false)
    }
}

impl Default for PoKOfCommitsProof {
    fn default() -> Self {
        Self {
            commits: Vec::new(),
            commits_proofs: Vec::new(),
        }
    }
}

try_from_impl!(PoKOfCommitsProof, BBSError);
serdes_impl!(PoKOfCommitsProof);
#[cfg(feature = "wasm")]
wasm_slice_impl!(PoKOfCommitsProof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate;
    use crate::prelude::Signature;
    use crate::{HashElem, RandomElem};

    #[test]
    fn pok_commits_all_committed_messages() {
        let ghash: Vec<u8> = vec![
            9, 244, 226, 211, 240, 138, 206, 72, 201, 12, 2, 194, 102, 36, 104, 46, 152, 186, 54,
            130, 75, 42, 226, 196, 249, 220, 252, 251, 43, 253, 68, 51, 254, 240, 245, 74, 92, 88,
            131, 54, 115, 22, 68, 245, 53, 52, 251, 32, 15, 150, 145, 173, 222, 69, 1, 77, 131,
            108, 129, 0, 253, 232, 211, 190, 211, 244, 225, 230, 31, 226, 252, 125, 112, 28, 86,
            204, 138, 57, 84, 15, 172, 55, 225, 129, 57, 10, 162, 163, 8, 51, 193, 22, 17, 234,
            164, 169,
        ];
        let mut g = GeneratorG1::try_from(&ghash[..]).unwrap();

        let hhash: Vec<u8> = vec![
            9, 55, 153, 174, 136, 245, 47, 156, 167, 167, 232, 41, 182, 145, 90, 87, 83, 186, 229,
            58, 182, 180, 75, 121, 73, 114, 4, 157, 208, 223, 212, 136, 121, 66, 71, 175, 118, 5,
            46, 122, 197, 35, 204, 63, 207, 225, 39, 44, 25, 144, 147, 56, 57, 204, 8, 78, 39, 94,
            220, 40, 123, 233, 91, 89, 87, 11, 143, 241, 162, 164, 16, 136, 94, 29, 18, 58, 124,
            77, 175, 97, 107, 199, 161, 165, 196, 90, 94, 204, 224, 26, 72, 137, 3, 147, 161, 5,
        ];
        let h = GeneratorG1::try_from(&hhash[..]).unwrap();

        let message_count = 5;
        let mut messages = Vec::new();
        for _ in 0..message_count {
            messages.push(SignatureMessage::random());
        }

        let (verkey, signkey) = generate(message_count).unwrap();

        let sig = Signature::new(messages.as_slice(), &signkey, &verkey).unwrap();
        let res = sig.verify(messages.as_slice(), &verkey);
        assert!(res.unwrap());
        let proof_messages = vec![
            pm_committed_raw!(messages[0].clone()),
            pm_committed_raw!(messages[1].clone()),
            pm_committed_raw!(messages[2].clone()),
            pm_committed_raw!(messages[3].clone()),
            pm_committed_raw!(messages[4].clone()),
        ];

        let pok = PoKOfCommits::init(&proof_messages, &g, &h).unwrap();
        let challenge_prover = ProofChallenge::hash(&pok.to_bytes());
        let proof = pok.gen_proof(&challenge_prover).unwrap();

        // Test to_bytes
        let proof_bytes = proof.to_bytes_uncompressed_form();
        let proof_cp = PoKOfCommitsProof::from_bytes_uncompressed_form(&proof_bytes);
        assert!(proof_cp.is_ok());

        let proof_bytes = proof.to_bytes_compressed_form();
        let proof_cp = PoKOfCommitsProof::from_bytes_compressed_form(&proof_bytes);
        assert!(proof_cp.is_ok());

        // The verifier generates the challenge on its own.
        let challenge_bytes = proof.get_bytes_for_challenge(&g, &h);
        let challenge_verifier = ProofChallenge::hash(&challenge_bytes);
        assert_eq!(challenge_prover, challenge_verifier);

        assert_eq!(
            proof.verify(&challenge_verifier, &g, &h).unwrap(),
            PoKOfCommitsProofStatus::Success
        );
    }
}
