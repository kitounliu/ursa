extern crate merlin;
use bulletproofs_amcl as bulletproofs;

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, Variable, Verifier};

#[cfg(test)]
mod tests {
    use super::*;
    use amcl_wrapper::field_elem::FieldElement;
    use amcl_wrapper::group_elem::GroupElement;
    use amcl_wrapper::group_elem_g1::{G1Vector, G1};
    use bulletproofs::utils::get_generators;
    use merlin::Transcript;
    use serde::Serialize;

    #[test]
    fn test_2_factors_r1cs() {
        // Prove knowledge of `p` and `q` such that given an `r`, `p * q = r`
        let big_g: G1Vector = get_generators("G", 8).into();
        let big_h: G1Vector = get_generators("H", 8).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let mut factors = vec![
            (
                FieldElement::from(17u32),
                FieldElement::from(19u32),
                FieldElement::from(323u32),
            ),
            (
                FieldElement::from(7u32),
                FieldElement::from(5u32),
                FieldElement::from(35u32),
            ),
        ];

        let (proof, mut commitments) = {
            let mut comms = vec![];
            let mut prover_transcript = Transcript::new(b"Factors");
            let mut prover = Prover::new(&g, &h, &mut prover_transcript);

            for (p, q, r) in &factors {
                let (com_p, var_p) = prover.commit(p.clone(), FieldElement::random());
                let (com_q, var_q) = prover.commit(q.clone(), FieldElement::random());
                let (_, _, o) = prover.multiply(var_p.into(), var_q.into());
                let lc: LinearCombination = vec![(Variable::One(), r.clone())].iter().collect();
                prover.constrain(o - lc);
                comms.push(com_p);
                comms.push(com_q);
            }

            let proof = prover.prove(&big_g, &big_h).unwrap();

            (proof, comms)
        };

        println!("Proving done");

        let mut verifier_transcript = Transcript::new(b"Factors");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        for (_, _, r) in factors.drain(0..) {
            let var_p = verifier.commit(commitments.remove(0));
            let var_q = verifier.commit(commitments.remove(0));
            let (_, _, o) = verifier.multiply(var_p.into(), var_q.into());
            let lc: LinearCombination = vec![(Variable::One(), r)].iter().collect();
            verifier.constrain(o - lc);
        }

        assert!(verifier.verify(&proof, &g, &h, &big_g, &big_h).is_ok());
    }

    #[test]
    fn test_amcl_conversion() {
        let gg = G1::generator();
        println!("\namcl: generator = {:?}", gg);
        let ggb = gg.to_bytes();
        println!("\namcl: bytes of generator = {:?}", ggb);

        let bb: Vec<u8> = vec![
            4, 16, 115, 15, 248, 200, 84, 98, 99, 25, 30, 12, 225, 124, 224, 95, 47, 45, 127, 243,
            213, 193, 64, 97, 74, 48, 218, 26, 93, 202, 250, 193, 27, 92, 27, 124, 76, 178, 196,
            150, 50, 84, 233, 45, 156, 80, 111, 68, 49, 9, 136, 207, 244, 94, 231, 164, 90, 207,
            153, 26, 204, 35, 45, 124, 33, 43, 156, 234, 69, 162, 11, 148, 151, 233, 252, 1, 152,
            243, 168, 114, 247, 103, 120, 115, 209, 121, 212, 146, 103, 174, 176, 166, 166, 30,
            172, 244, 95,
        ];
        let gbb = G1::from_bytes(&bb).unwrap();
        println!("\namcl: gbb = {:?}", gbb);

        let mut g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());
        println!("\namcl: Hash(g) = {:?}", g);
        let gb = g.to_bytes();
        println!("\namcl: bytes of Hash(g) = {:?}, length = {}", gb, gb.len());
        let hb = h.to_bytes();
        println!("\namcl: bytes of Hash(h) = {:?}", hb);

        let gg = G1::from_bytes(&gb).unwrap();
        println!("\n hash(g) from bytes = {:?}", gg);

        let age = FieldElement::from(25u32);
        let age_bytes = age.to_bytes();
        println!(
            "\namcl: bytes of age = {:?}, length = {:?}",
            age_bytes,
            age_bytes.len()
        );

        let r = FieldElement::random();
        let r_bytes = r.to_bytes();
        println!(
            "\namcl: random fieldelement = {:?}, length = {:?}",
            r_bytes,
            r_bytes.len()
        );

        let ga = g.scalar_mul_const_time(&age);
        println!("\n amcl: g^age = {:?}", ga);
        let gab = ga.to_bytes();
        println!("\n amcl: bytes of g^age = {:?}", gab);
    }

    #[test]
    fn test_factor_r1cs() {
        // Prove knowledge of `p`, `q`, `r` and `s` such that given an `s`, `p * q * r = s`
        let big_g: G1Vector = get_generators("G", 8).into();
        let big_h: G1Vector = get_generators("H", 8).into();
        let g = G1::from_msg_hash("g".as_bytes());
        let h = G1::from_msg_hash("h".as_bytes());

        let mut factors = vec![
            (
                FieldElement::from(2u32),
                FieldElement::from(4u32),
                FieldElement::from(6u32),
                FieldElement::from(48u32),
            ),
            (
                FieldElement::from(7u32),
                FieldElement::from(5u32),
                FieldElement::from(35u32),
                FieldElement::from(1225u32),
            ),
        ];

        let (proof, mut commitments) = {
            let mut comms = vec![];
            let mut prover_transcript = Transcript::new(b"Factors");
            let mut prover = Prover::new(&g, &h, &mut prover_transcript);

            for (p, q, r, s) in &factors {
                let (com_p, var_p) = prover.commit(p.clone(), FieldElement::random());
                let (com_q, var_q) = prover.commit(q.clone(), FieldElement::random());
                let (com_r, var_r) = prover.commit(r.clone(), FieldElement::random());
                let (_, _, o1) = prover.multiply(var_p.into(), var_q.into());
                let (_, _, o2) = prover.multiply(o1.into(), var_r.into());
                let lc: LinearCombination = vec![(Variable::One(), s.clone())].iter().collect();
                prover.constrain(o2 - lc);
                comms.push(com_p);
                comms.push(com_q);
                comms.push(com_r);
            }

            let proof = prover.prove(&big_g, &big_h).unwrap();

            (proof, comms)
        };

        println!("Proving done");

        let mut verifier_transcript = Transcript::new(b"Factors");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        for (_, _, _, s) in factors.drain(0..) {
            let var_p = verifier.commit(commitments.remove(0));
            let var_q = verifier.commit(commitments.remove(0));
            let var_r = verifier.commit(commitments.remove(0));
            let (_, _, o1) = verifier.multiply(var_p.into(), var_q.into());
            let (_, _, o2) = verifier.multiply(o1.into(), var_r.into());
            let lc: LinearCombination = vec![(Variable::One(), s)].iter().collect();
            verifier.constrain(o2 - lc);
        }

        assert!(verifier.verify(&proof, &g, &h, &big_g, &big_h).is_ok());
    }
}
