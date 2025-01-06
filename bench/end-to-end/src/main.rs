use halo2_proofs::{
    arithmetic::Field,
    circuit::Value,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof
        , ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        }
        ,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand_core::OsRng;
use halo2_link_circuit::circuit::CircuitChainedPolyEval;

const K: u32 = 6;
const POLY_DEGREE: usize = 4;

fn generate_inputs(poly_degree: usize) -> (Vec<Fr>, Fr, Fr) {
    let a: Vec<Fr> = (0..poly_degree).map(|_| Fr::random(OsRng)).collect();
    let b = Fr::random(OsRng);

    let mut sum = Fr::zero();
    let mut b_pow = Fr::one();
    for x in a.iter() {
        sum += x * b_pow;
        b_pow *= &b;
    }

    // (a, b, sum)
    (vec![Fr::from(2), Fr::from(3), Fr::from(4), Fr::from(5)], Fr::from(10), Fr::from(5432))
}


fn keygen() -> (ParamsKZG<Bn256>, ProvingKey<G1Affine>) {
    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::new(K);
    let unknown_a_vec = vec![Value::unknown(); POLY_DEGREE];
    let empty_circuit: CircuitChainedPolyEval<Fr> = CircuitChainedPolyEval {
        a: unknown_a_vec,
        b: Value::unknown(),
        poly_degree: POLY_DEGREE,
    };

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    (params, pk)
}

fn prover(params: &ParamsKZG<Bn256>, pk: &ProvingKey<G1Affine>, a: Vec<Fr>, b: Fr, sum: Fr) -> Vec<u8> {
    let rng = OsRng;

    let circuit: CircuitChainedPolyEval<Fr> = CircuitChainedPolyEval {
        a: a.iter().map(|x| Value::known(*x)).collect(),
        b: Value::known(b),
        poly_degree: POLY_DEGREE,
    };

    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<Bn256>,
        Challenge255<G1Affine>,
        OsRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        CircuitChainedPolyEval<Fr>,
    >(params, pk, &[circuit], &[&[&[sum]]], rng, &mut transcript)
        .expect("proof generation should not fail");

    transcript.finalize()
}

fn verifier(params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, sum: Fr, proof: &[u8]) {
    let params_verifier = params.verifier_params();
    let strategy = SingleStrategy::new(&params_verifier);
    let mut transcript = Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(proof);

    // assert!(verify_proof::<
    //     KZGCommitmentScheme<Bn256>,
    //     VerifierSHPLONK<Bn256>,
    //     Challenge255<G1Affine>,
    //     Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>,
    //     SingleStrategy<Bn256>,
    // >(&params_verifier, vk, strategy, &[&[&[sum]]], &mut transcript)
    //     .is_ok());

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<Bn256>,
    >(&params_verifier, vk, strategy, &[&[&[sum]]], &mut transcript).unwrap();
}

fn main() {
    let (a, b, sum) = generate_inputs(POLY_DEGREE);

    let (params, pk) = keygen();
    let proof = prover(&params, &pk, a, b, sum);
    verifier(&params, pk.get_vk(), sum, proof.as_ref());
}