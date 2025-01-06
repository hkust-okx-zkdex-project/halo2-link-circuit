use ff::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ConfigChainedEval {
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,
    pub(crate) b_cur: Column<Advice>,
    pub(crate) b_next: Column<Advice>,
    pub(crate) acc_cur: Column<Advice>,
    pub(crate) acc_next: Column<Advice>,

    pub instance: Column<Instance>,

    selector_b: Selector,
    selector_acc: Selector,
}

struct ChipChainedEval<F: Field> {
    config: ConfigChainedEval,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for ChipChainedEval<F> {
    type Config = ConfigChainedEval;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> ChipChainedEval<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        // a: Column<Advice>,
        // b: Column<Advice>,
        // b_cur: Column<Advice>,
        // b_next: Column<Advice>,
        // acc_cur: Column<Advice>,
        // acc_next: Column<Advice>,
        // constants: Column<Fixed>,
        // instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let b_cur = meta.advice_column();
        let b_next = meta.advice_column();
        let acc_cur = meta.advice_column();
        let acc_next = meta.advice_column();
        let constants = meta.fixed_column();
        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(b_cur);
        meta.enable_equality(b_next);
        meta.enable_equality(acc_cur);
        meta.enable_equality(acc_next);

        meta.enable_constant(constants);

        meta.enable_equality(instance);

        let selector_b = meta.selector();
        let selector_acc = meta.selector();

        meta.create_gate("chained_eval", |meta| {
            let val_a = meta.query_advice(a, Rotation::cur());
            let val_b = meta.query_advice(b, Rotation::cur());
            let val_b_cur = meta.query_advice(b_cur, Rotation::cur());
            let val_b_next = meta.query_advice(b_next, Rotation::cur());
            let val_acc_cur = meta.query_advice(acc_cur, Rotation::cur());
            let val_acc_next = meta.query_advice(acc_next, Rotation::cur());
            let selector_b = meta.query_selector(selector_b);
            let selector_acc = meta.query_selector(selector_acc);

            vec![
                selector_b * (val_b_next - val_b * val_b_cur.clone()),
                selector_acc * (val_acc_next - (val_acc_cur + val_a * val_b_cur)),
            ]
        });

        ConfigChainedEval {
            a,
            b,
            b_cur,
            b_next,
            acc_cur,
            acc_next,
            instance,
            selector_b,
            selector_acc,
        }
    }
}

#[derive(Default)]
pub struct CircuitChainedPolyEval<F: Field> {
    pub a: Vec<Value<F>>,
    pub b: Value<F>,
    pub poly_degree: usize,
}

impl<F: Field> Circuit<F> for CircuitChainedPolyEval<F> {
    type Config = ConfigChainedEval;

    type FloorPlanner = SimpleFloorPlanner;

    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ChipChainedEval::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let mut cells_b: Vec<AssignedCell<F, F>> = Vec::with_capacity(self.poly_degree);
        let mut cells_b_cur: Vec<AssignedCell<F, F>> = Vec::with_capacity(self.poly_degree);
        let mut cells_b_next: Vec<AssignedCell<F, F>> = Vec::with_capacity(self.poly_degree);
        let mut cells_acc_cur: Vec<AssignedCell<F, F>> = Vec::with_capacity(self.poly_degree);
        let mut cells_acc_next: Vec<AssignedCell<F, F>> = Vec::with_capacity(self.poly_degree);

        layouter.assign_region(
            || "chained eval",
            |mut region| {
                let cell_b_cur =
                    region.assign_advice_from_constant(|| "b_cur", config.b_cur, 0, F::ONE)?;
                cells_b_cur.push(cell_b_cur.clone());
                let mut val_b_cur = cell_b_cur.value().copied();

                let cell_acc_cur =
                    region.assign_advice_from_constant(|| "acc_cur", config.acc_cur, 0, F::ZERO)?;
                cells_acc_cur.push(cell_acc_cur.clone());
                let mut val_acc_cur = cell_acc_cur.value().copied();

                for i in 0..self.poly_degree {
                    config.selector_b.enable(&mut region, i)?;
                    config.selector_acc.enable(&mut region, i)?;

                    region.assign_advice(|| "a", config.a, i, || self.a[i])?;

                    // let cell_b = region.assign_advice(|| "b", config.b, i, || self.b)?;
                    let cell_b = region.assign_advice_from_instance(
                        || "b",
                        config.instance,
                        0,
                        config.b,
                        i,
                    )?;
                    cells_b.push(cell_b);

                    if i != 0 {
                        let cell_b_cur =
                            region.assign_advice(|| "b_cur", config.b_cur, i, || val_b_cur)?;
                        cells_b_cur.push(cell_b_cur);
                    }

                    let val_b_next = val_b_cur * self.b;
                    let cell_b_next =
                        region.assign_advice(|| "b_next", config.b_next, i, || val_b_next)?;
                    cells_b_next.push(cell_b_next);

                    if i != 0 {
                        let cell_acc_cur = region.assign_advice(
                            || "acc_cur",
                            config.acc_cur,
                            i,
                            || val_acc_cur,
                        )?;
                        cells_acc_cur.push(cell_acc_cur);
                    }

                    let val_acc_next = val_acc_cur + self.a[i] * val_b_cur;
                    let cell_acc_next =
                        region.assign_advice(|| "acc_next", config.acc_next, i, || val_acc_next)?;
                    cells_acc_next.push(cell_acc_next);

                    val_b_cur = val_b_next;
                    val_acc_cur = val_acc_next;
                }

                for i in 0..(self.poly_degree - 1) {
                    region.constrain_equal(cells_b_cur[i + 1].cell(), cells_b_next[i].cell())?;
                    region
                        .constrain_equal(cells_acc_cur[i + 1].cell(), cells_acc_next[i].cell())?;
                }

                Ok(())
            },
        )?;

        layouter.constrain_instance(cells_acc_next.last().unwrap().cell(), config.instance, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;

    #[test]
    fn test_chained_eval_circuit() {
        const POLY_DEGREE: usize = 4;
        let a_vals = [2, 3, 4, 5].map(Fr::from);
        let b_val = Fr::from(10);
        let sum_val = Fr::from(5432);

        // Build the circuit
        let circuit = CircuitChainedPolyEval::<Fr> {
            a: a_vals.iter().map(|&x| Value::known(x)).collect(),
            b: Value::known(b_val),
            poly_degree: POLY_DEGREE,
        };

        // Public inputs
        let public_inputs = vec![b_val, sum_val];

        // Set a small k that can handle 4 rows
        let k = 6;

        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(
            prover.verify(),
            Ok(()),
            "Proof should succeed with correct input"
        );

        // If we tweak the final sum, it should fail:
        let wrong_sum = sum_val + Fr::ONE;
        let public_inputs_wrong = vec![b_val, wrong_sum];

        let prover = MockProver::run(k, &circuit, vec![public_inputs_wrong]).unwrap();
        assert!(prover.verify().is_err(), "Proof should fail with wrong sum");
    }
}
