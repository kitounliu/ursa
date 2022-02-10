use amcl_wrapper::constants::{GroupG1_SIZE as AMCL_G1_SIZE, MODBYTES as AMCL_FR_SIZE};
use amcl_wrapper::field_elem::FieldElement as AMCL_Fr;
use amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1 as AMCL_G1;
use pairing_plus::bls12_381::{Fr, G1};
use pairing_plus::serdes::SerDes;

use crate::{FR_COMPRESSED_SIZE, G1_UNCOMPRESSED_SIZE};

const PP_FR_START: usize = AMCL_FR_SIZE - FR_COMPRESSED_SIZE;

/// convert  pairing_plus Fr into amcl field element bytes
pub fn pp_fr_to_amcl_fr_bytes(fr: &Fr) -> Vec<u8> {
    let mut fr_bytes = Vec::new();
    fr.serialize(&mut fr_bytes, false).unwrap();
    let mut buffer = [0u8; AMCL_FR_SIZE];
    buffer[PP_FR_START..].copy_from_slice(&fr_bytes);
    buffer.to_vec()
}

/// convert amcl field element bytes to pairing_plus Fr
pub fn pp_fr_from_amcl_fr_bytes(fr_bytes: &[u8; AMCL_FR_SIZE]) -> Fr {
    assert_eq!([0u8; PP_FR_START], fr_bytes[0..PP_FR_START]);
    let mut buffer = [0u8; FR_COMPRESSED_SIZE];
    buffer.copy_from_slice(&fr_bytes[PP_FR_START..]);
    Fr::deserialize(&mut &buffer[..], false).unwrap()
}

/// convert amcl field element into Fr bytes in pairing_plus
pub fn amcl_fr_to_pp_bytes(fr: &AMCL_Fr) -> Vec<u8> {
    let fr_bytes = fr.to_bytes();
    assert_eq!(
        [0u8; PP_FR_START][..],
        fr_bytes[0..PP_FR_START],
        "leading bytes should be zero and the data should be in the remaining bytes."
    );
    fr_bytes[PP_FR_START..].to_vec()
}

/// convert pairing_plus Fr bytes to amcl field element
pub fn amcl_fr_from_pp_bytes(fr_bytes: &[u8; FR_COMPRESSED_SIZE]) -> AMCL_Fr {
    let mut buffer = [0u8; AMCL_FR_SIZE];
    buffer[PP_FR_START..].copy_from_slice(fr_bytes);
    AMCL_Fr::from_bytes(&buffer).unwrap()
}

/// convert pairing_plus uncompressed G1 to amcl G1 element bytes
pub fn pp_g1_uncompressed_to_amcl_g1_bytes(g1: &G1) -> Vec<u8> {
    let mut bytes = vec![];
    g1.serialize(&mut bytes, false)
        .expect("unable to serialize G1");
    let mut buffer = [0u8; AMCL_G1_SIZE];
    buffer[0] = 4u8;
    buffer[1..].copy_from_slice(&bytes);
    buffer.to_vec()
}

/// convert amcl G1 element bytes to pairing_plus uncompressed G1
pub fn pp_g1_uncompressed_from_amcl_g1_bytes(g1_bytes: &[u8; AMCL_G1_SIZE]) -> G1 {
    assert_eq!(g1_bytes[0], 4u8);
    let mut buffer = [0u8; G1_UNCOMPRESSED_SIZE];
    buffer.copy_from_slice(&g1_bytes[1..]);
    G1::deserialize(&mut &buffer[..], false).unwrap()
}

/// convert amcl G1 element into uncompressed pairing_plus G1 bytes
pub fn amcl_g1_to_pp_bytes_uncompressed(g1: &AMCL_G1) -> Vec<u8> {
    let g1_bytes = g1.to_bytes();
    assert_eq!(G1_UNCOMPRESSED_SIZE + 1, g1_bytes.len());
    assert_eq!(
        g1_bytes[0], 4u8,
        "leading byte should be 4 which indicating uncompressed bytes."
    );
    g1_bytes[1..].to_vec()
}

/// convert uncompressed pairing_plus G1 bytes into amcl G1 bytes
pub fn amcl_g1_from_pp_bytes_uncompressed(g1_bytes: &[u8; G1_UNCOMPRESSED_SIZE]) -> AMCL_G1 {
    let mut buffer = [0u8; AMCL_G1_SIZE];
    buffer[0] = 4u8;
    buffer[1..].copy_from_slice(g1_bytes);
    AMCL_G1::from_bytes(&buffer).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing_plus::{
        bls12_381::{Fr, G1},
        hash_to_field::BaseFromRO,
        CurveAffine, CurveProjective,
    };

    use crate::FR_UNCOMPRESSED_SIZE;
    use blake2::digest::generic_array::GenericArray;

    #[test]
    fn pp_amcl_conversion() {
        let mut okm = [0u8; FR_UNCOMPRESSED_SIZE];
        let r = Fr::from_okm(GenericArray::from_slice(&okm[..]));
        let amcl_bytes = pp_fr_to_amcl_fr_bytes(&r);
        AMCL_Fr::from_bytes(&amcl_bytes).unwrap();

        let g = G1::one();
        let amcl_g_bytes = pp_g1_uncompressed_to_amcl_g1_bytes(&g);
        let amcl_g = AMCL_G1::from_bytes(&amcl_g_bytes).unwrap();
        let gg = AMCL_G1::generator();
        assert_eq!(amcl_g, gg);

        let mut h = AMCL_G1::from_msg_hash("h".as_bytes());
        let h_bytes = amcl_g1_to_pp_bytes_uncompressed(&h);
        let hh = vec![
            9, 55, 153, 174, 136, 245, 47, 156, 167, 167, 232, 41, 182, 145, 90, 87, 83, 186, 229,
            58, 182, 180, 75, 121, 73, 114, 4, 157, 208, 223, 212, 136, 121, 66, 71, 175, 118, 5,
            46, 122, 197, 35, 204, 63, 207, 225, 39, 44, 25, 144, 147, 56, 57, 204, 8, 78, 39, 94,
            220, 40, 123, 233, 91, 89, 87, 11, 143, 241, 162, 164, 16, 136, 94, 29, 18, 58, 124,
            77, 175, 97, 107, 199, 161, 165, 196, 90, 94, 204, 224, 26, 72, 137, 3, 147, 161, 5,
        ];
        assert_eq!(h_bytes, hh)
    }
}
