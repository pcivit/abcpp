mod certificates;
mod crypto;
use std::sync::Arc;

use crate::{certificates::benchmark::*, crypto::public_params::PublicParams};

fn main() {
    let n = 10000;
    //let rho = 1.0;
    let lambda = 1582.0; //(n as f64)*rho
    let n_eval = 1 + 1;
    let step = 0;
    let hash_value = [1u8; 32];

    let params = Arc::new(PublicParams {
        n,
        lambda,
        epsilon: 0.13333333333, //0.333
        delta: 0.21,            //0.0
        kappa_hash: 256,
        kappa_msig: 256,
        kappa_vrf: 256,
    });

    println!("Run setup for n: {:?} ...", n,);

    let (ca, materials) = run_setup(n);

    println!("Run (sequentially) n={:?} elections, with lambda: {:?} ...", n, params.lambda,);

    let (mut parties, submissions, eligible_ids) =
        generate_parties_and_submissions(step, hash_value, &ca, &params, &materials);

    println!(
        "nb elections: {:?}, for a quorum threshold of W={:?}",
        eligible_ids.len(),
        params.quorum_threshold(),
    );

    println!(
        "Run (sequentially) {:?} aggregation(s), for a quorum threshold of W={:?} ...",
        (n_eval - 1),
        params.quorum_threshold(),
    );

    let mode = crate::certificates::quorum::AggregationMode::SuperOptimistic;
    let (duration_rat_max, duration_rat_tot) =
        run_ratification(&mut parties, &submissions, mode, n_eval);

    println!(
        "The maximum measured duration of computing a quorum certificate among {:?} samples is {:?}, while the average is {:?}",
        (n_eval - 1),
        duration_rat_max,
        duration_rat_tot.checked_div((n_eval - 1).try_into().unwrap()).unwrap(),
    );

    println!(
        "Run (sequentially) {:?} verifications(s), for a quorum threshold of W={:?} ...",
        (n_eval - 1),
        params.quorum_threshold(),
    );

    let (duration_prop_max, duration_prop_tot) = run_propagation(step, &mut parties, n_eval);

    println!(
        "The maximum measured duration of verifying a quorum certificate among {:?} samples is {:?}, while the average is {:?}",
        (n_eval - 1),
        duration_prop_max,
        duration_prop_tot.checked_div((n_eval - 1).try_into().unwrap()).unwrap(),
    );
}
