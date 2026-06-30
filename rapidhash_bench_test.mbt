// Performance benchmarks for rapidhash V3.
//
// Each input size targets a distinct code path:
//   - 8 / 16    : the `len <= 16` fast paths (typical hash-map keys)
//   - 64 / 112  : the 16<len<=112 unrolled ladder
//   - 1 KiB     : the >112 block path
//   - 64 KiB    : the 224-byte unrolled main loop (bulk throughput)
//
// `b.keep(...)` is required so the optimizer cannot drop the pure call.
// Run with: moon test --target native -p DzmingLi/rapidhash

///|
/// One bench per size, reported side-by-side. Inputs are reused across runs so
/// allocation/setup is excluded from the timed region.
test (b : @bench.T) {
  let d8 = buf(8)
  let d16 = buf(16)
  let d64 = buf(64)
  let d112 = buf(112)
  let d1k = buf(1024)
  let d64k = buf(64 * 1024)
  b.bench(name="len=8", fn() { b.keep(@rapidhash.rapidhash(d8)) })
  b.bench(name="len=16", fn() { b.keep(@rapidhash.rapidhash(d16)) })
  b.bench(name="len=64", fn() { b.keep(@rapidhash.rapidhash(d64)) })
  b.bench(name="len=112", fn() { b.keep(@rapidhash.rapidhash(d112)) })
  b.bench(name="len=1KiB", fn() { b.keep(@rapidhash.rapidhash(d1k)) })
  b.bench(name="len=64KiB", fn() { b.keep(@rapidhash.rapidhash(d64k)) })
}

///|
/// Hash-map-style workload: many short keys (e.g. identifiers / small strings).
/// Sums the hashes so none of the calls can be optimized away.
test (b : @bench.T) {
  let keys = Array::makei(1000, fn(i) { buf(4 + i % 13) })
  b.bench(name="1000 short keys (4..16 B)", fn() {
    let mut acc : UInt64 = 0
    for k in keys {
      acc = acc ^ @rapidhash.rapidhash(k)
    }
    b.keep(acc)
  })
}
