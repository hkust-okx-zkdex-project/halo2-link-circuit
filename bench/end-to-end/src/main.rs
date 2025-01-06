use std::env;
use halo2_link_circuit::circuit::CircuitChainedPolyEval;
use halo2_proofs::{
    arithmetic::Field,
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand_core::OsRng;

// const K: u32 = 6;
// const POLY_DEGREE: usize = 4;

fn generate_inputs(poly_degree: usize) -> (Vec<Fr>, Fr, Fr) {
    let a: Vec<Fr> = (0..poly_degree).map(|_| Fr::random(OsRng)).collect();
    let b = Fr::random(OsRng);

    let mut sum = Fr::zero();
    let mut b_pow = Fr::one();
    for x in a.iter() {
        sum += x * b_pow;
        b_pow *= &b;
    }

    (a, b, sum)
}

fn keygen(k: u32, poly_degree: usize) -> (ParamsKZG<Bn256>, ProvingKey<G1Affine>) {
    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::new(k);
    let unknown_a_vec = vec![Value::unknown(); poly_degree];
    let empty_circuit: CircuitChainedPolyEval<Fr> = CircuitChainedPolyEval {
        a: unknown_a_vec,
        b: Value::unknown(),
        poly_degree,
    };

    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    (params, pk)
}

fn prover(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    a: Vec<Fr>,
    b: Fr,
    sum: Fr,
    poly_degree: usize,
) -> Vec<u8> {
    let rng = OsRng;

    let circuit: CircuitChainedPolyEval<Fr> = CircuitChainedPolyEval {
        a: a.iter().map(|x| Value::known(*x)).collect(),
        b: Value::known(b),
        poly_degree,
    };

    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<Bn256>,
        Challenge255<G1Affine>,
        OsRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        CircuitChainedPolyEval<Fr>,
    >(
        params,
        pk,
        &[circuit],
        &[&[&[b, sum]]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    transcript.finalize()
}

fn verifier(params: &ParamsKZG<Bn256>, vk: &VerifyingKey<G1Affine>, b: Fr, sum: Fr, proof: &[u8]) {
    let params_verifier = params.verifier_params();
    let strategy = SingleStrategy::new(&params_verifier);
    let mut transcript = Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(proof);

    assert!(verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<Bn256>,
    >(
        &params_verifier,
        vk,
        strategy,
        &[&[&[b, sum]]],
        &mut transcript
    )
    .is_ok());
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <k> <poly_degree>", args[0]);
        std::process::exit(1);
    }

    let k: u32 = args[1].parse().expect("Invalid value for k");
    let poly_degree: usize = args[2].parse().expect("Invalid value for poly_degree");

    println!("K: {}", k);
    println!("POLY_DEGREE: {}", poly_degree);
    let (a, b, sum) = generate_inputs(poly_degree);

    let curr_time = std::time::Instant::now();
    let (params, pk) = keygen(k, poly_degree);
    println!("Keygen time (ms): {:?}", curr_time.elapsed().as_millis());

    let curr_time = std::time::Instant::now();
    let proof = prover(&params, &pk, a, b, sum, poly_degree);
    println!("Proving time (ms): {:?}", curr_time.elapsed().as_millis());

    let curr_time = std::time::Instant::now();
    verifier(&params, pk.get_vk(), b, sum, proof.as_ref());
    println!("Verification time (ms): {:?}", curr_time.elapsed().as_millis());
}
