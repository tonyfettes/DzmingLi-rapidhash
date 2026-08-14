# tonyfettes/rapidhash

A faithful MoonBit port of [**rapidhash V3**](https://github.com/Nicoshev/rapidhash) —
a very fast, high-quality, **non-cryptographic** 64-bit hash. rapidhash is the
official successor to wyhash and the fastest hash to pass SMHasher/SMHasher3 with
near-ideal collision probability.

Use it for hash maps, content keys, checksums, and dedup — **not** for security.

## Install

```bash
moon add tonyfettes/rapidhash
```

## Usage

```mbt nocheck
///|
test {
  // 64-bit hash of any `Bytes`.
  let h = @rapidhash.rapidhash(b"hello world")
  inspect(@rapidhash.to_hex(h), content="2f27cb27d5240940")

  // Seed it to get an independent hash family.
  let seeded = @rapidhash.rapidhash(b"hello world", seed=42)
  inspect(h == seeded, content="false")
}
```

## Benchmarks

Cross-implementation latency and throughput benchmarks live in
[tonyfettes/hash-benchmarks](https://github.com/tonyfettes/hash-benchmarks).
This module keeps correctness tests alongside the implementation.

## Notes

- **64-bit output**, little-endian reads — bit-for-bit compatible with the
  reference C (and any other conformant rapidhash V3), validated against
  reference-generated known-answer vectors across every input-length class.
- **Pure MoonBit**, no FFI, no dependencies, all backends.
- The 64×64→128 multiply (`rapid_mum`) lowers to the machine's native wide
  multiply on release native builds via the `%u64.mul_wide` intrinsic — a
  single `mulq` on x86-64, `mul`+`umulh` on arm64. Debug builds and the
  js/wasm backends run a portable 32-bit-split `umul128` (MoonBit has no
  `UInt128`), matching the reference's portable fallback.
- Non-cryptographic: do not use where collision resistance against an adversary
  matters.
