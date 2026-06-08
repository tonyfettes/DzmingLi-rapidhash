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
/// Full 64×64 → 128-bit product as `(lo, hi)`, schoolbook via 32-bit halves —
/// exactly the reference's portable fallback (MoonBit has no `UInt128`). All
/// arithmetic wraps mod 2⁶⁴.
fn umul128(a : UInt64, b : UInt64) -> (UInt64, UInt64) {
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
  (lo, hi)
}

///|
/// `rapid_mix`: multiply-fold the two words (unprotected/FAST default = `A=lo,
/// B=hi`), then xor the halves.
fn mix(a : UInt64, b : UInt64) -> UInt64 {
  let (lo, hi) = umul128(a, b)
  lo ^ hi
}

///|
/// Little-endian `UInt64` from `data[p..p+8]`.
fn read64(data : Bytes, p : Int) -> UInt64 {
  let mut v : UInt64 = 0
  for i in 0..<8 {
    v = v | (data[p + i].to_uint64() << (i * 8))
  }
  v
}

///|
/// Little-endian `UInt32` (zero-extended) from `data[p..p+4]`.
fn read32(data : Bytes, p : Int) -> UInt64 {
  let mut v : UInt64 = 0
  for i in 0..<4 {
    v = v | (data[p + i].to_uint64() << (i * 8))
  }
  v
}

///|
/// rapidhash V3 of `data` with an optional `seed` (default 0). 64-bit output.
///
/// ```mbt
/// let h = @rapidhash.rapidhash(b"abc")
/// inspect(@rapidhash.to_hex(h), content="cb475beafa9c0da2")
/// // A different seed gives a different hash.
/// inspect(h == @rapidhash.rapidhash(b"abc", seed=1), content="false")
/// ```
pub fn rapidhash(data : Bytes, seed~ : UInt64 = 0) -> UInt64 {
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
        a = read64(data, p)
        b = read64(data, p + len - 8)
      } else {
        a = read32(data, p)
        b = read32(data, p + len - 4)
      }
    } else if len > 0 {
      a = (data[0].to_uint64() << 45) | data[len - 1].to_uint64()
      b = data[len >> 1].to_uint64()
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
        seed = mix(read64(data, p) ^ S0, read64(data, p + 8) ^ seed)
        see1 = mix(read64(data, p + 16) ^ S1, read64(data, p + 24) ^ see1)
        see2 = mix(read64(data, p + 32) ^ S2, read64(data, p + 40) ^ see2)
        see3 = mix(read64(data, p + 48) ^ S3, read64(data, p + 56) ^ see3)
        see4 = mix(read64(data, p + 64) ^ S4, read64(data, p + 72) ^ see4)
        see5 = mix(read64(data, p + 80) ^ S5, read64(data, p + 88) ^ see5)
        see6 = mix(read64(data, p + 96) ^ S6, read64(data, p + 104) ^ see6)
        seed = mix(read64(data, p + 112) ^ S0, read64(data, p + 120) ^ seed)
        see1 = mix(read64(data, p + 128) ^ S1, read64(data, p + 136) ^ see1)
        see2 = mix(read64(data, p + 144) ^ S2, read64(data, p + 152) ^ see2)
        see3 = mix(read64(data, p + 160) ^ S3, read64(data, p + 168) ^ see3)
        see4 = mix(read64(data, p + 176) ^ S4, read64(data, p + 184) ^ see4)
        see5 = mix(read64(data, p + 192) ^ S5, read64(data, p + 200) ^ see5)
        see6 = mix(read64(data, p + 208) ^ S6, read64(data, p + 216) ^ see6)
        p = p + 224
        i = i - 224
      }
      if i > 112 {
        seed = mix(read64(data, p) ^ S0, read64(data, p + 8) ^ seed)
        see1 = mix(read64(data, p + 16) ^ S1, read64(data, p + 24) ^ see1)
        see2 = mix(read64(data, p + 32) ^ S2, read64(data, p + 40) ^ see2)
        see3 = mix(read64(data, p + 48) ^ S3, read64(data, p + 56) ^ see3)
        see4 = mix(read64(data, p + 64) ^ S4, read64(data, p + 72) ^ see4)
        see5 = mix(read64(data, p + 80) ^ S5, read64(data, p + 88) ^ see5)
        see6 = mix(read64(data, p + 96) ^ S6, read64(data, p + 104) ^ see6)
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
      seed = mix(read64(data, p) ^ S2, read64(data, p + 8) ^ seed)
      if i > 32 {
        seed = mix(read64(data, p + 16) ^ S2, read64(data, p + 24) ^ seed)
        if i > 48 {
          seed = mix(read64(data, p + 32) ^ S1, read64(data, p + 40) ^ seed)
          if i > 64 {
            seed = mix(read64(data, p + 48) ^ S1, read64(data, p + 56) ^ seed)
            if i > 80 {
              seed = mix(read64(data, p + 64) ^ S2, read64(data, p + 72) ^ seed)
              if i > 96 {
                seed = mix(read64(data, p + 80) ^ S1, read64(data, p + 88) ^ seed)
              }
            }
          }
        }
      }
    }
    a = read64(data, p + i - 16) ^ i.to_uint64()
    b = read64(data, p + i - 8)
  }
  a = a ^ S1
  b = b ^ seed
  let (lo, hi) = umul128(a, b)
  mix(lo ^ S7, hi ^ S1 ^ i.to_uint64())
}

///|
/// `rapidhash` formatted as 16 lowercase hex chars (big-endian nibble order).
///
/// ```mbt
/// inspect(@rapidhash.to_hex(@rapidhash.rapidhash(b"abc")), content="cb475beafa9c0da2")
/// ```
pub fn to_hex(hash : UInt64) -> String {
  let hexchars = "0123456789abcdef".to_array()
  let buf = StringBuilder::new()
  for k in 0..<16 {
    buf.write_char(hexchars[((hash >> ((15 - k) * 4)) & 0xF).to_int()])
  }
  buf.to_string()
}
