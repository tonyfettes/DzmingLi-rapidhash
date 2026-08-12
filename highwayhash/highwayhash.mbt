// HighwayHash — a faithful MoonBit port of the reference C++ portable
// implementation (google/highwayhash, hh_portable.h).
//
// Unlike rapidhash/wyhash/xxh3, HighwayHash never needs the high 64 bits of a
// 64×64 product: its *only* multiply is 32×32 → 64 (a single `mul`, or v128's
// `i64x2_extmul_*_i32x4_u`), so it carries no `umulh` / `__int128` dependency
// and no portable-schoolbook penalty. It is a keyed, hash-flooding-resistant
// PRF with a 256-bit key; this file provides the 64-bit output.
//
// Validated against the reference's own published known-answer vectors
// (highwayhash_test.cc, kExpected64) — see the tests.

///|
/// Reference `init0` / `init1` (the Reset constants).
let init0 : FixedArray[UInt64] = [
  0xdbe6d5d5fe4cce2f, 0xa4093822299f31d0, 0x13198a2e03707344, 0x243f6a8885a308d3,
]

///|
let init1 : FixedArray[UInt64] = [
  0x3bd39e10cb0ef593, 0xc0acf169b5f18a8c, 0xbe5466cf34e90c6c, 0x452821e638d01377,
]

///|
/// The four 256-bit-wide accumulator lanes. Array contents are mutated in place.
priv struct State {
  v0 : FixedArray[UInt64]
  v1 : FixedArray[UInt64]
  mul0 : FixedArray[UInt64]
  mul1 : FixedArray[UInt64]
}

///|
/// Rotate a 64-bit word by 32 (swap halves) — reference `Rotate64By32`.
fn rot32(x : UInt64) -> UInt64 {
  (x >> 32) | (x << 32)
}

///|
/// `Reset`: seed the state from the 256-bit key.
fn State::new(k0 : UInt64, k1 : UInt64, k2 : UInt64, k3 : UInt64) -> State {
  let key : FixedArray[UInt64] = [k0, k1, k2, k3]
  let v0 = FixedArray::make(4, 0UL)
  let v1 = FixedArray::make(4, 0UL)
  let mul0 = FixedArray::make(4, 0UL)
  let mul1 = FixedArray::make(4, 0UL)
  for i in 0..<4 {
    mul0[i] = init0[i]
    mul1[i] = init1[i]
    v0[i] = init0[i] ^ key[i]
    v1[i] = init1[i] ^ rot32(key[i])
  }
  { v0, v1, mul0, mul1 }
}

///|
/// Clears all bits except one byte at offset `b` — reference `MASK`.
fn mask(v : UInt64, b : Int) -> UInt64 {
  v & (0xFFUL << (b * 8))
}

///|
/// `ZipperMergeAndAdd`: a 16-byte permutation, added into `add[i1]`/`add[i0]`.
fn zipper(
  v1 : UInt64,
  v0 : UInt64,
  add : FixedArray[UInt64],
  i1 : Int,
  i0 : Int,
) -> Unit {
  add[i0] = add[i0] +
    (
      ((mask(v0, 3) + mask(v1, 4)) >> 24) +
      ((mask(v0, 5) + mask(v1, 6)) >> 16) +
      mask(v0, 2) +
      (mask(v0, 1) << 32) +
      (mask(v1, 7) >> 8) +
      (v0 << 56)
    )
  add[i1] = add[i1] +
    (
      ((mask(v1, 3) + mask(v0, 4)) >> 24) +
      mask(v1, 2) +
      (mask(v1, 5) >> 16) +
      (mask(v1, 1) << 24) +
      (mask(v0, 6) >> 8) +
      (mask(v1, 0) << 48) +
      mask(v0, 7)
    )
}

///|
/// `Update`: fold one 32-byte packet (4 native-order lanes) into the state.
fn State::update(self : State, lanes : FixedArray[UInt64]) -> Unit {
  let v0 = self.v0
  let v1 = self.v1
  let mul0 = self.mul0
  let mul1 = self.mul1
  for i in 0..<4 {
    v1[i] = v1[i] + lanes[i] + mul0[i]
  }
  for lane in 0..<4 {
    let v1_32 = v1[lane] & 0xFFFFFFFF
    mul0[lane] = mul0[lane] ^ (v1_32 * (v0[lane] >> 32))
    v0[lane] = v0[lane] + mul1[lane]
    let v0_32 = v0[lane] & 0xFFFFFFFF
    mul1[lane] = mul1[lane] ^ (v0_32 * (v1[lane] >> 32))
  }
  zipper(v1[1], v1[0], v0, 1, 0)
  zipper(v1[3], v1[2], v0, 3, 2)
  zipper(v0[1], v0[0], v1, 1, 0)
  zipper(v0[3], v0[2], v1, 3, 2)
}

///|
/// `PermuteAndUpdate`: rotate-permute v0 into a packet and fold it back in.
fn State::permute_and_update(self : State) -> Unit {
  let v0 = self.v0
  let permuted : FixedArray[UInt64] = [
    rot32(v0[2]),
    rot32(v0[3]),
    rot32(v0[0]),
    rot32(v0[1]),
  ]
  self.update(permuted)
}

///|
/// Little-endian `UInt64` assembled from `buf[base..base+8]`.
fn le64(buf : FixedArray[Byte], base : Int) -> UInt64 {
  let mut r = 0UL
  for k in 0..<8 {
    r = r | (buf[base + k].to_uint64() << (k * 8))
  }
  r
}

///|
/// `UpdateRemainder`: fold the final 1..31 bytes with HighwayHash's length
/// padding (a `mod 32` injection + a 32-bit rotation of v1 + a Load3-built
/// final packet). Cold path; correctness over speed.
fn State::update_remainder(
  self : State,
  data : Bytes,
  p : Int,
  rem : Int,
) -> Unit {
  let v0 = self.v0
  let v1 = self.v1
  let mod32_pair = (rem.to_uint64() << 32) + rem.to_uint64()
  for i in 0..<4 {
    v0[i] = v0[i] + mod32_pair
  }
  // Rotate32By: rotate each of the 8 u32 halves of v1 left by `rem` (1..31).
  for i in 0..<4 {
    let lo = v1[i] & 0xFFFFFFFF
    let hi = v1[i] >> 32
    let lo2 = ((lo << rem) | (lo >> (32 - rem))) & 0xFFFFFFFF
    let hi2 = ((hi << rem) | (hi >> (32 - rem))) & 0xFFFFFFFF
    v1[i] = lo2 | (hi2 << 32)
  }
  // Build the final 32-byte packet (zero-filled, then the remainder + Load3).
  let packet = FixedArray::make(32, b'\x00')
  let full = rem / 4 * 4
  for k in 0..<full {
    packet[k] = data[p + k]
  }
  if rem >= 16 {
    // Load3 AllowReadBeforeAndReturn: the last 4 raw bytes, placed at packet[28].
    for k in 0..<4 {
      packet[28 + k] = data[p + rem - 4 + k]
    }
  } else {
    // Load3 AllowUnordered: bytes at idx 0, m4>>1, m4-1, placed at packet[16].
    let m4 = rem % 4
    if m4 != 0 {
      let r = p + full
      packet[16] = data[r]
      packet[17] = data[r + m4 / 2]
      packet[18] = data[r + m4 - 1]
    }
  }
  let lanes : FixedArray[UInt64] = [
    le64(packet, 0),
    le64(packet, 8),
    le64(packet, 16),
    le64(packet, 24),
  ]
  self.update(lanes)
}

///|
/// `Finalize` (64-bit): 4 permute rounds, then combine lane 0.
fn State::finalize64(self : State) -> UInt64 {
  for _ in 0..<4 {
    self.permute_and_update()
  }
  self.v0[0] + self.v1[0] + self.mul0[0] + self.mul1[0]
}

///|
fn read64(data : Bytes, p : Int) -> UInt64 {
  data.unsafe_read_uint64_le(p)
}

///|
/// HighwayHash-64 of `data` under a 256-bit key `(k0,k1,k2,k3)` (default 0).
/// Output matches the reference C++ portable implementation.
///
/// ```mbt nocheck
/// let h = @highwayhash.highwayhash64(b"abc")
/// ```
pub fn highwayhash64(
  data : Bytes,
  k0? : UInt64 = 0,
  k1? : UInt64 = 0,
  k2? : UInt64 = 0,
  k3? : UInt64 = 0,
) -> UInt64 {
  let st = State::new(k0, k1, k2, k3)
  let len = data.length()
  let truncated = len / 32 * 32
  let lanes = FixedArray::make(4, 0UL)
  let mut p = 0
  while p < truncated {
    lanes[0] = read64(data, p)
    lanes[1] = read64(data, p + 8)
    lanes[2] = read64(data, p + 16)
    lanes[3] = read64(data, p + 24)
    st.update(lanes)
    p = p + 32
  }
  let rem = len - truncated
  if rem != 0 {
    st.update_remainder(data, p, rem)
  }
  st.finalize64()
}

///|
/// `highwayhash64` formatted as 16 lowercase hex chars.
pub fn to_hex(hash : UInt64) -> String {
  let hexchars = "0123456789abcdef".to_array()
  let buf = StringBuilder::new()
  for k in 0..<16 {
    buf.write_char(hexchars[((hash >> ((15 - k) * 4)) & 0xF).to_int()])
  }
  buf.to_string()
}
