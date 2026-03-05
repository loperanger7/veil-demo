// VEIL — Load Test / Benchmark
// Ticket: VEIL-301
//
// Performance benchmarks for the relay service.
// Target: 10,000 concurrent connections, p99 < 100ms.
//
// These benchmarks use criterion for statistical rigor:
//   - Multiple iterations with warmup
//   - Statistical analysis of variance
//   - Outlier detection
//
// Run with: cargo bench --bench load

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use prost::Message;

/// Create a test storage and app state.
fn setup_storage() -> (sled::Db, veil_relay::storage::Storage) {
    let config = sled::Config::new().temporary(true);
    let db = config.open().expect("failed to open temp sled");

    let storage = veil_relay::storage::Storage {
        accounts: veil_relay::storage::accounts::AccountStore::new(&db).unwrap(),
        prekeys: veil_relay::storage::prekey_store::PrekeyStore::new(&db).unwrap(),
        messages: veil_relay::storage::message_queue::MessageQueue::new(&db).unwrap(),
    };

    (db, storage)
}

/// Benchmark: message enqueue throughput.
fn bench_enqueue(c: &mut Criterion) {
    let (_db, storage) = setup_storage();

    // Pre-register a device
    let reg_id = storage
        .accounts
        .register_device(1, vec![0xAA; 32])
        .unwrap();

    let envelope = veil_relay::proto::VeilEnvelope {
        content: vec![0x42; 256],
        sealed_sender: vec![0x99; 128],
        content_type: 1,
        source_registration_id: 0,
        source_device_id: 0,
        server_guid: vec![],
        server_timestamp: 0,
    };

    c.bench_function("enqueue_message", |b| {
        b.iter(|| {
            storage
                .messages
                .enqueue(
                    black_box(reg_id),
                    black_box(1),
                    black_box(envelope.clone()),
                )
                .unwrap();
        });
    });
}

/// Benchmark: message retrieve throughput at various queue depths.
fn bench_retrieve(c: &mut Criterion) {
    let mut group = c.benchmark_group("retrieve_messages");

    for queue_size in [10, 100, 1000] {
        let (_db, storage) = setup_storage();
        let reg_id = storage
            .accounts
            .register_device(1, vec![0xAA; 32])
            .unwrap();

        // Pre-populate queue
        for _ in 0..queue_size {
            let envelope = veil_relay::proto::VeilEnvelope {
                content: vec![0x42; 256],
                sealed_sender: vec![0x99; 128],
                content_type: 1,
                source_registration_id: 0,
                source_device_id: 0,
                server_guid: vec![],
                server_timestamp: 0,
            };
            storage.messages.enqueue(reg_id, 1, envelope).unwrap();
        }

        group.bench_with_input(
            BenchmarkId::new("queue_depth", queue_size),
            &queue_size,
            |b, _| {
                b.iter(|| {
                    let msgs = storage
                        .messages
                        .retrieve(black_box(reg_id), black_box(1))
                        .unwrap();
                    black_box(msgs);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark: prekey bundle fetch.
fn bench_prekey_fetch(c: &mut Criterion) {
    let (_db, storage) = setup_storage();
    let reg_id = storage
        .accounts
        .register_device(1, vec![0xAA; 32])
        .unwrap();

    let bundle = veil_relay::proto::PrekeyBundle {
        identity_key: vec![0xAA; 32],
        signed_prekey: vec![0xBB; 32],
        signed_prekey_signature: vec![0xCC; 64],
        one_time_prekeys: (0..100).map(|i| vec![i as u8; 32]).collect(),
        pq_kem_public_key: Some(vec![0xFF; 1568]),
        pq_kem_signature: Some(vec![0x11; 64]),
    };

    storage.prekeys.store_bundle(reg_id, &bundle).unwrap();

    c.bench_function("fetch_prekey_bundle", |b| {
        b.iter(|| {
            let bundle = storage
                .prekeys
                .fetch_bundle(black_box(reg_id))
                .unwrap();
            black_box(bundle);
        });
    });
}

/// Benchmark: anonymous token signing.
fn bench_token_signing(c: &mut Criterion) {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    let signing_key = veil_relay::auth::anonymous_token::TokenSigningKey::generate().unwrap();
    let config = sled::Config::new().temporary(true);
    let db = config.open().unwrap();
    let service =
        veil_relay::auth::anonymous_token::AnonymousTokenService::new(signing_key, &db).unwrap();

    // Pre-generate blinded tokens
    let blinded_tokens: Vec<veil_relay::auth::anonymous_token::BlindedToken> = (0..100)
        .map(|_| {
            let r = Scalar::random(&mut rand::thread_rng());
            let point = &r * RISTRETTO_BASEPOINT_TABLE;
            veil_relay::auth::anonymous_token::BlindedToken {
                point: point.compress().to_bytes().to_vec(),
            }
        })
        .collect();

    c.bench_function("sign_100_tokens", |b| {
        b.iter(|| {
            let signed = service
                .sign_blinded_tokens(black_box(&blinded_tokens))
                .unwrap();
            black_box(signed);
        });
    });
}

criterion_group!(
    benches,
    bench_enqueue,
    bench_retrieve,
    bench_prekey_fetch,
    bench_token_signing
);
criterion_main!(benches);
