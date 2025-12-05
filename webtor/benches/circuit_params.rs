//! Criterion microbenchmarks for circuit parameters
//!
//! Run with: cargo bench -p webtor --bench circuit_params
//!
//! These benchmarks are deterministic and don't require network access.

use criterion::{criterion_group, criterion_main, Criterion, black_box};

/// Benchmark circuit parameter construction
/// This is a CPU-bound operation that happens during circuit creation.
fn bench_make_circ_params(c: &mut Criterion) {
    use webtor::circuit::make_circ_params;
    
    c.bench_function("make_circ_params", |b| {
        b.iter(|| {
            black_box(make_circ_params().unwrap())
        })
    });
}

/// Benchmark relay selection algorithm
fn bench_relay_selection(c: &mut Criterion) {
    use webtor::relay::{Relay, RelayManager, flags};
    
    // Create a set of test relays
    let relays: Vec<Relay> = (0..1000).map(|i| {
        let flags = match i % 4 {
            0 => vec![flags::FAST, flags::STABLE, flags::GUARD, flags::VALID],
            1 => vec![flags::FAST, flags::STABLE, flags::VALID],
            2 => vec![flags::FAST, flags::STABLE, flags::EXIT, flags::VALID],
            _ => vec![flags::FAST, flags::STABLE, flags::V2DIR, flags::VALID],
        };
        Relay::new(
            format!("{:040x}", i),
            format!("relay_{}", i),
            format!("192.168.{}.{}", i / 256, i % 256),
            9001,
            flags.into_iter().map(String::from).collect(),
            format!("{:064x}", i),
        )
    }).collect();
    
    let manager = RelayManager::new(relays);
    
    c.bench_function("select_guard_relay", |b| {
        b.iter(|| {
            black_box(manager.select_guard().unwrap())
        })
    });
    
    c.bench_function("select_middle_relay", |b| {
        b.iter(|| {
            black_box(manager.select_middle().unwrap())
        })
    });
    
    c.bench_function("select_exit_relay", |b| {
        b.iter(|| {
            black_box(manager.select_exit().unwrap())
        })
    });
}

criterion_group!(benches, bench_make_circ_params, bench_relay_selection);
criterion_main!(benches);
