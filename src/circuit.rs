use ff::Field;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Instance, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

const POLY_DEGREE: usize = 4;

trait NumericInstructions<F: Field>: Chip<F> {
    /// Variable representing a number.
    type Num;

    /// Loads a number into the circuit as a private input.
    fn load_private(
        &self,
        layouter: impl Layouter<F>,
        a: &[Value<F>],
    ) -> Result<Vec<Self::Num>, ErrorFront>;

    /// Exposes a number as a public input to the circuit.
    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), ErrorFront>;
}

#[derive(Clone, Debug)]
pub struct ConfigChainedEval {
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,
    pub(crate) b_curr: Column<Advice>,
    pub(crate) b_next: Column<Advice>,
    pub(crate) acc_curr: Column<Advice>,
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
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        a: Column<Advice>,
        b: Column<Advice>,
        b_curr: Column<Advice>,
        b_next: Column<Advice>,
        acc_curr: Column<Advice>,
        acc_next: Column<Advice>,
        instance: Column<Instance>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(b_curr);
        meta.enable_equality(b_next);
        meta.enable_equality(acc_curr);
        meta.enable_equality(acc_next);

        meta.enable_equality(instance);

        let selector_b = meta.selector();
        let selector_acc = meta.selector();

        meta.create_gate("chained_eval", |meta| {
            let val_a = meta.query_advice(a, Rotation::cur());
            let val_b = meta.query_advice(b, Rotation::cur());
            let val_b_curr = meta.query_advice(b_curr, Rotation::cur());
            let val_b_next = meta.query_advice(b_next, Rotation::cur());
            let val_acc_curr = meta.query_advice(acc_curr, Rotation::cur());
            let val_acc_next = meta.query_advice(acc_next, Rotation::cur());
            let selector_b = meta.query_selector(selector_b);
            let selector_acc = meta.query_selector(selector_acc);

            vec![
                selector_b *( val_b_next - val_b * val_b_curr.clone()),
                selector_acc * (val_acc_next - (val_acc_curr + val_a * val_b_curr)),
            ]
        });

        ConfigChainedEval {
            a,
            b,
            b_curr,
            b_next,
            acc_curr,
            acc_next,
            instance,
            selector_b,
            selector_acc,
        }
    }
}

// #[derive(Clone)]
// struct Number<F: Field>(AssignedCell<F, F>);
//
// impl<F: Field> NumericInstructions<F> for ChipChainedEval<F> {
//     type Num = Number<F>;
//
//     fn load_private(
//         &self,
//         mut layouter: impl Layouter<F>,
//         a: &[Value<F>],
//     ) -> Result<Vec<Self::Num>, ErrorFront> {
//         let config = self.config();
//
//         // layouter.assign_region()
//         let results = a.iter().map(|a| {
//             layouter.assi
//                 || "a",
//                 config.a,
//                 a.clone(),
//             )?;
//             Ok(Number(layouter.get_value(config.a, 0)?))
//         }).collect::<Result<Vec<_>, _>>()?;
//
//         Ok(results)
//     }
// }

#[derive(Default)]
struct CircuitChainedPolyEval<F: Field> {
    a: Vec<Value<F>>,
    b: Value<F>,
    zero: Value<F>,
    one: Value<F>,
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
        let a = meta.advice_column();
        let b = meta.advice_column();
        let b_curr = meta.advice_column();
        let b_next = meta.advice_column();
        let acc_curr = meta.advice_column();
        let acc_next = meta.advice_column();

        let instance = meta.instance_column();

        ChipChainedEval::configure(meta, a, b, b_curr, b_next, acc_curr, acc_next, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let mut cells_b: Vec<AssignedCell<F, F>> = Vec::with_capacity(POLY_DEGREE);
        let mut cells_acc_curr: Vec<AssignedCell<F, F>> = Vec::with_capacity(POLY_DEGREE);

        layouter.assign_region(
            || "chained eval",
            |mut region| {
                let mut val_b_curr = self.one;
                let mut val_acc_curr = self.zero;

                for i in 0..POLY_DEGREE {
                    region.assign_advice(|| "a", config.a, i, || self.a[i])?;

                    let cell_b = region.assign_advice(|| "b", config.b, i, || self.b)?;
                    cells_b.push(cell_b);

                    region.assign_advice(|| "b_curr", config.b_curr, i, || val_b_curr)?;

                    let val_b_next = val_b_curr * self.b;
                    region.assign_advice(|| "b_next", config.b_next, i, || val_b_next)?;

                    region.assign_advice(|| "acc_curr", config.acc_curr, i, || val_acc_curr)?;

                    let val_acc_next = val_acc_curr + self.a[i] * val_b_curr;
                    let cell_acc_next =
                        region.assign_advice(|| "acc_next", config.acc_next, i, || val_acc_next)?;
                    cells_acc_curr.push(cell_acc_next);

                    val_b_curr = val_b_next;
                    val_acc_curr = val_acc_next;
                }

                Ok(())
            },
        )?;

        cells_b.iter().enumerate().try_for_each(|(i, cell_b)| {
            layouter.constrain_instance(cell_b.cell(), config.instance, 0)?;

            layouter.constrain_instance(
                cells_acc_curr.last().unwrap().cell(),
                config.instance,
                1,
            )?;

            Ok(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2curves::bn256::Fr;
    // or any other Field you'd like

    #[test]
    fn test_chained_eval_circuit() {
        // Suppose we want to evaluate:
        //   sum_{i=0}^{3} a_i * b^i
        // with a_0..a_3 = [2,3,4,5], b=10
        // => result = 2 + 3*10 + 4*100 + 5*1000 = 2 + 30 + 400 + 5000 = 5432
        //
        // We'll place:
        //   instance(0) = b,
        //   instance(1) = final sum,
        // so the public inputs are [b, sum].

        let a_vals = [2, 3, 4, 5].map(Fr::from);
        let b_val = Fr::from(10);
        // let mut sum_val = Fr::ZERO;
        // let mut pow_b = Fr::ONE;
        let sum_val = Fr::from(5432);
        // for &a_
        // sum_val should be 5432

        // Build the circuit
        let circuit = CircuitChainedPolyEval::<Fr> {
            a: a_vals.iter().map(|&x| Value::known(x)).collect(),
            b: Value::known(b_val),
            zero: Value::known(Fr::ZERO),
            one: Value::known(Fr::ONE),
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
        //
        // // If we tweak the final sum, it should fail:
        // let wrong_sum = sum_val + Fr::ONE;
        // let public_inputs_wrong = vec![b_val, wrong_sum];
        //
        // let prover = MockProver::run(k, &circuit, vec![public_inputs_wrong]).unwrap();
        // assert!(prover.verify().is_err(), "Proof should fail with wrong sum");
    }
}
