use halo2_link_circuit::circuit::CircuitChainedPolyEval;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves::bn256::Fr;
use plotters::prelude::*;

fn main() {
    const POLY_DEGREE: usize = 4;
    let a_vals = [2, 3, 4, 5].map(Fr::from);
    let b_val = Fr::from(10);

    // Build the circuit
    let circuit = CircuitChainedPolyEval::<Fr> {
        a: a_vals.iter().map(|&x| Value::known(x)).collect(),
        b: Value::known(b_val),
        zero: Value::known(Fr::ZERO),
        one: Value::known(Fr::ONE),
        poly_degree: POLY_DEGREE,
    };

    let root = BitMapBackend::new("layout.png", (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Example Circuit Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .view_width(0..16)
        .view_height(0..16)
        .show_labels(true)
        .show_equality_constraints(true)
        .mark_equality_cells(true)
        .render(5, &circuit, &root)
        .unwrap();
}
