// rapidhash V3 — a very fast, high-quality, non-cryptographic hash.
//
// A faithful MoonBit port of the reference C
// (github.com/Nicoshev/rapidhash). rapidhash is the official successor to wyhash
// and the fastest hash to pass SMHasher/SMHasher3 with near-ideal collision
// probability. Output is 64-bit; reads are little-endian (the canonical layout).
// It is NOT cryptographic — use it for hash maps, content keys, checksums, and
// dedup, not for security.
//
// The constants, length classes, multiply-fold (`mum`/`mix`), and final
// avalanche match the reference exactly; the port is validated against
// reference-generated known-answer vectors (see the tests).

///|
/// The eight default secret constants (reference `rapid_secret[8]`).
const S0 : UInt64 = 0x2d358dccaa6c78a5UL

///|
const S1 : UInt64 = 0x8bb84b93962eacc9UL

///|
const S2 : UInt64 = 0x4b33a62ed433d4a3UL

///|
const S3 : UInt64 = 0x4d5a2da51de1aa47UL

///|
const S4 : UInt64 = 0xa0761d6478bd642fUL

///|
const S5 : UInt64 = 0xe7037ed1a0b428dbUL

///|
const S6 : UInt64 = 0x90ed1765281c388cUL

///|
const S7 : UInt64 = 0xaaaaaaaaaaaaaaaaUL

///|
/// A pair of 64-bit words returned by value. `#valtype` keeps it stack-allocated
/// on the native backend (no heap allocation, no refcount), so the hot loop's
/// 128-bit products and 16-byte loads build nothing on the heap — unlike a
/// tuple, which is a boxed object. On wasm/js the attribute is a no-op (ordinary
/// struct, same as the old tuple). Internal only; absent from the public API.
#valtype
priv struct Int64x2 {
  a : UInt64
  b : UInt64
}

///|
/// Full 64×64 → 128-bit product as `Int64x2{a: lo, b: hi}`.
///
/// On release native builds the compiler lowers this to the machine's native
/// 128-bit multiply via the `%u64.mul_wide` intrinsic — `mul`+`umulh` on arm64,
/// a single `mulq` on x86-64 (the C runtime helper uses `__int128`). Debug
/// builds and the js/wasm backends do not lower `Mul_wide` yet
/// ("mul_wide is not supported by the machine backend yet"), so they silently
/// run the schoolbook body below — the reference's portable fallback, exact and
/// portable, and the correctness backstop for every backend. Field order
/// `a=lo, b=hi` matches the intrinsic's positional write.
#intrinsic("%u64.mul_wide")
fn umul128(a : UInt64, b : UInt64) -> Int64x2 {
  let ha = a >> 32
  let hb = b >> 32
  let la = a & 0xffffffff
  let lb = b & 0xffffffff
  let rh = ha * hb
  let rm0 = ha * lb
  let rm1 = hb * la
  let rl = la * lb
  let t = rl + (rm0 << 32)
  let mut c : UInt64 = if t < rl { 1 } else { 0 }
  let lo = t + (rm1 << 32)
  c = c + (if lo < t { 1 } else { 0 })
  let hi = rh + (rm0 >> 32) + (rm1 >> 32) + c
  { a: lo, b: hi }
}

///|
/// `rapid_mix`: multiply-fold the two words (unprotected/FAST default = `A=lo,
/// B=hi`), then xor the halves.
fn mix(a : UInt64, b : UInt64) -> UInt64 {
  let p = umul128(a, b)
  p.a ^ p.b
}

///|
/// Little-endian `UInt64` from `data[p..p+8]`.
fn read64(data : Bytes, p : Int) -> UInt64 {
  data.unsafe_read_uint64_le(p)
}

///|
/// Two little-endian `UInt64`s from `data[p..p+16]` as `Int64x2{a, b}`.
///
/// Implemented as two adjacent `unsafe_read_uint64_le` (each lowers to a
/// single unaligned 64-bit load) instead of a `v128_load` + lane extracts:
/// on arm64 the v128 round-trip costs `ldr q` + `mov.d` + `fmov` per 16 B
/// and pushes the hot loop's register pressure (spills, in-loop constant
/// rematerialization); the two scalar loads go straight into GPRs and the C
/// backend merges them into a single `ldp` pair load.
fn read64x2(data : Bytes, p : Int) -> Int64x2 {
  { a: data.unsafe_read_uint64_le(p), b: data.unsafe_read_uint64_le(p + 8) }
}

///|
fn mix64x2(data : Bytes, p : Int, secret : UInt64, seed : UInt64) -> UInt64 {
  let pr = read64x2(data, p)
  mix(pr.a ^ secret, pr.b ^ seed)
}

///|
/// Little-endian `UInt32` (zero-extended) from `data[p..p+4]`.
fn read32(data : Bytes, p : Int) -> UInt64 {
  data.unsafe_read_uint32_le(p).to_uint64()
}

///|
/// rapidhash V3 of `data` with an optional `seed` (default 0). 64-bit output.
///
/// ```mbt nocheck
/// let h = @rapidhash.rapidhash(b"abc")
/// inspect(@rapidhash.to_hex(h), content="cb475beafa9c0da2")
/// // A different seed gives a different hash.
/// inspect(h == @rapidhash.rapidhash(b"abc", seed=1), content="false")
/// ```
pub fn rapidhash(data : Bytes, seed? : UInt64 = 0) -> UInt64 {
  let len = data.length()
  let mut seed = seed ^ mix(seed ^ S2, S1)
  let mut a : UInt64 = 0
  let mut b : UInt64 = 0
  let mut i = len
  let mut p = 0
  if len <= 16 {
    if len >= 4 {
      seed = seed ^ len.to_uint64()
      if len >= 8 {
        if len == 16 {
          let pr = read64x2(data, p)
          a = pr.a
          b = pr.b
        } else {
          a = read64(data, p)
          b = read64(data, p + len - 8)
        }
      } else {
        a = read32(data, p)
        b = read32(data, p + len - 4)
      }
    } else if len > 0 {
      // 1 <= len <= 3 here, so indices 0, len-1, len>>1 are all in bounds;
      // `unsafe_get` (a builtin intrinsic, portable across backends) skips the
      // bounds check. The hot paths already read via `unsafe_read_*` / v128.
      a = (data.unsafe_get(0).to_uint64() << 45) |
        data.unsafe_get(len - 1).to_uint64()
      b = data.unsafe_get(len >> 1).to_uint64()
    }
    // len == 0: a = b = 0.
  } else {
    if len > 112 {
      let mut see1 = seed
      let mut see2 = seed
      let mut see3 = seed
      let mut see4 = seed
      let mut see5 = seed
      let mut see6 = seed
      while i > 224 {
        seed = mix64x2(data, p, S0, seed)
        see1 = mix64x2(data, p + 16, S1, see1)
        see2 = mix64x2(data, p + 32, S2, see2)
        see3 = mix64x2(data, p + 48, S3, see3)
        see4 = mix64x2(data, p + 64, S4, see4)
        see5 = mix64x2(data, p + 80, S5, see5)
        see6 = mix64x2(data, p + 96, S6, see6)
        seed = mix64x2(data, p + 112, S0, seed)
        see1 = mix64x2(data, p + 128, S1, see1)
        see2 = mix64x2(data, p + 144, S2, see2)
        see3 = mix64x2(data, p + 160, S3, see3)
        see4 = mix64x2(data, p + 176, S4, see4)
        see5 = mix64x2(data, p + 192, S5, see5)
        see6 = mix64x2(data, p + 208, S6, see6)
        p = p + 224
        i = i - 224
      }
      if i > 112 {
        seed = mix64x2(data, p, S0, seed)
        see1 = mix64x2(data, p + 16, S1, see1)
        see2 = mix64x2(data, p + 32, S2, see2)
        see3 = mix64x2(data, p + 48, S3, see3)
        see4 = mix64x2(data, p + 64, S4, see4)
        see5 = mix64x2(data, p + 80, S5, see5)
        see6 = mix64x2(data, p + 96, S6, see6)
        p = p + 112
        i = i - 112
      }
      seed = seed ^ see1
      see2 = see2 ^ see3
      see4 = see4 ^ see5
      seed = seed ^ see6
      see2 = see2 ^ see4
      seed = seed ^ see2
    }
    if i > 16 {
      seed = mix64x2(data, p, S2, seed)
      if i > 32 {
        seed = mix64x2(data, p + 16, S2, seed)
        if i > 48 {
          seed = mix64x2(data, p + 32, S1, seed)
          if i > 64 {
            seed = mix64x2(data, p + 48, S1, seed)
            if i > 80 {
              seed = mix64x2(data, p + 64, S2, seed)
              if i > 96 {
                seed = mix64x2(data, p + 80, S1, seed)
              }
            }
          }
        }
      }
    }
    let pr = read64x2(data, p + i - 16)
    a = pr.a ^ i.to_uint64()
    b = pr.b
  }
  a = a ^ S1
  b = b ^ seed
  let prod = umul128(a, b)
  mix(prod.a ^ S7, prod.b ^ S1 ^ i.to_uint64())
}

///|
let hexchars : FixedArray[Char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
]

///|
/// `rapidhash` formatted as 16 lowercase hex chars (big-endian nibble order).
///
/// ```mbt nocheck
/// inspect(@rapidhash.to_hex(@rapidhash.rapidhash(b"abc")), content="cb475beafa9c0da2")
/// ```
pub fn to_hex(hash : UInt64) -> String {
  let buf = StringBuilder::new()
  for k in 0..<16 {
    buf.write_char(hexchars[((hash >> ((15 - k) * 4)) & 0xF).to_int()])
  }
  buf.to_string()
}
