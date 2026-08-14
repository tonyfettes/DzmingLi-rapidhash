// Benchmarks mirroring the upstream reference harness
// (github.com/Nicoshev/rapidhash/tree/master/bench, itself the xxHash bench
// tool). Same data and the same two headline metrics:
//
//   * latency    — a serial dependency chain: each hash's result picks the next
//                  input, so the CPU cannot overlap consecutive calls. This is
//                  upstream's `bench_latency_smallInputs` / `benchLatency`, and
//                  the number it advertises for 4/8/16-byte keys.
//   * throughput — back-to-back independent hashes over one large buffer,
//                  upstream's `bench_largeInput`.
//
// Input bytes use upstream's `initBuffer` fill (a multiplicative PRNG), not
// zeros or a ramp, so nothing along the way is data-dependent-shortcuttable.
//
// Run:  moon bench --target native --release
// `moon bench` reports mean ± σ plus a min column; upstream takes the min run.
// Latency rows read directly as ns/hash. For throughput, GB/s = bytes / ns.

///|
/// Upstream `initBuffer`: `acc` starts at k2, then per byte `acc *= k1; byte =
/// acc >> 56`. `Bytes::makei` invokes the closure for indices 0,1,…,n-1 in
/// order, so the mutable accumulator reproduces the reference stream exactly.
fn init_buffer(size : Int) -> Bytes {
  let k1 : UInt64 = 11400714785074694791UL
  let mut acc : UInt64 = 14029467366897019727UL
  Bytes::makei(size, fn(_i) {
    acc = acc * k1
    (acc >> 56).to_byte()
  })
}

///|
/// Upstream `MARGIN_FOR_LATENCY` / `START_MASK`: the latency chain shifts the
/// input start by `hash & 1023` within a buffer carrying 1024 bytes of slack.
const LAT_MARGIN : Int = 1024

///|
/// The 1024 possible shifted inputs of a given `size`, precomputed once so the
/// timed region allocates nothing. `blocks[off]` is `size` bytes of the
/// reference stream starting at offset `off` — the MoonBit stand-in for
/// upstream's `src + (hash & START_MASK)` pointer bump (the public `rapidhash`
/// takes a whole `Bytes`, so the slices are materialized up front).
fn make_offset_blocks(size : Int) -> Array[Bytes] {
  let base = init_buffer(size + LAT_MARGIN)
  Array::makei(LAT_MARGIN, fn(off) {
    Bytes::makei(size, fn(j) { base[off + j] })
  })
}

///|
/// Serial latency for small keys (upstream sweeps 1..127; these are the
/// representative sizes plus the headline 4/8/16). Each call hashes the block
/// selected by the previous result, so calls form a dependency chain and the
/// reported time is one hash's latency.
test (b : @bench.T) {
  let mask = (LAT_MARGIN - 1).to_uint64()
  for size in [4, 8, 16, 32, 64, 128] {
    let blocks = make_offset_blocks(size)
    let mut h : UInt64 = 0
    b.bench(name="latency len=\{size}", fn() {
      h = @rapidhash.rapidhash(blocks[(h & mask).to_int()])
      b.keep(h)
    })
  }
}

///|
/// Peak throughput on large buffers (upstream uses powers of two up to 2^27;
/// these span 256 B … 1 MiB). Calls are independent, so the CPU overlaps them.
/// GB/s = size / (reported ns per call).
test (b : @bench.T) {
  for size in [256, 1024, 4096, 16384, 65536, 262144, 1048576] {
    let buf = init_buffer(size)
    b.bench(name="throughput len=\{size}", fn() {
      b.keep(@rapidhash.rapidhash(buf))
    })
  }
}
