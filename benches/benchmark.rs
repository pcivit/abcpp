use std::{sync::Arc, time::Duration};

use abcpp::{
    certificates::{benchmark::*, quorum::AggregationMode},
    crypto::public_params::PublicParams,
};
use criterion::{Criterion, criterion_group, criterion_main};

pub fn benchmark_rat_and_pure_prop(c: &mut Criterion) {
    let n = 10_000;
    let lambda = 1582.0;
    let n_eval = 2;
    let step = 0;
    let hash_value = [1u8; 32];

    let params = Arc::new(PublicParams {
        n,
        lambda,
        epsilon: 0.13333333333,
        delta: 0.21,
        kappa_hash: 256,
        kappa_msig: 256,
        kappa_vrf: 256,
    });

    let (ca, materials) = run_setup(n);
    let (parties, submissions, _) =
        generate_parties_and_submissions(step, hash_value, &ca, &params, &materials);

    // === Precompute ratification outside the benchmark ===
    let mut ratified_parties = parties.clone();
    run_ratification(&mut ratified_parties, &submissions, AggregationMode::SuperOptimistic, n_eval);

    let mut group = c.benchmark_group("aggregation_and_verification");
    group.sample_size(100);
    group.measurement_time(Duration::from_secs(65));

    // === Benchmark only aggregation ===
    group.bench_function("aggregation_only_super_optimistic", |b| {
        b.iter(|| {
            let mut parties_fresh = parties.clone();
            run_ratification(
                &mut parties_fresh,
                &submissions,
                AggregationMode::SuperOptimistic,
                n_eval,
            );
        });
    });

    group.bench_function("aggregation_only_optimistic", |b| {
        b.iter(|| {
            let mut parties_fresh = parties.clone();
            run_ratification(&mut parties_fresh, &submissions, AggregationMode::Optimistic, n_eval);
        });
    });

    group.bench_function("aggregation_only_pessimistic", |b| {
        b.iter(|| {
            let mut parties_fresh = parties.clone();
            run_ratification(
                &mut parties_fresh,
                &submissions,
                AggregationMode::Pessimistic,
                n_eval,
            );
        });
    });

    // === Benchmark only verification ===
    group.bench_function("verification_only", |b| {
        b.iter(|| {
            let mut parties_fresh = ratified_parties.clone(); // already contains certificates
            run_propagation(step, &mut parties_fresh, n_eval);
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_rat_and_pure_prop);
criterion_main!(benches);
