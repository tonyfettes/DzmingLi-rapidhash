// Known-answer vectors generated from the reference C (rapidhash V3, seed 0,
// little-endian). Inputs are byte buffers `[0,1,…,n-1]`, with `n` chosen to
// exercise every length class: the ≤16 sub-paths (0/1/2/3, 4-7, 8-16), the
// 16<len≤112 ladder (each `i>32/48/64/80/96` rung), the >112 block path, and the
// 224-byte unrolled loop. Plus an ASCII case and a seeded case.

///|
/// `[0, 1, …, n-1] (mod 256)` as `Bytes`.
fn buf(n : Int) -> Bytes {
  Bytes::makei(n, fn(i) { (i % 256).to_byte() })
}

///|
test "rapidhash V3 known-answer vectors (vs reference C)" {
  let cases : Array[(Int, String)] = [
    (0, "0338dc4be2cecdae"),
    (1, "4f23c791b16eba02"),
    (2, "fd31e98c893fa10f"),
    (3, "dbd091bcf57ae814"),
    (4, "46fef26db4943adf"),
    (7, "7f403e573bb8ebc1"),
    (8, "da56413ff396af3e"),
    (9, "e48a75b5cbf2af29"),
    (16, "d6bfc1bcf7e9ca19"),
    (17, "7508c9e74d5b5366"),
    (32, "c0186990f026b180"),
    (48, "ecd5ed3e946f9c91"),
    (49, "635a714c24c02d64"),
    (64, "d1a6cc5fe6cf87f4"),
    (80, "e7e477a0dffeae1f"),
    (96, "1e9a8d81b63de536"),
    (112, "667174637fd34ae7"),
    (113, "abaf0e2bdacf7e23"),
    (224, "eefa9c2e54fc0df1"),
    (225, "f6c6e7081ab8456d"),
    (256, "a2f383f4b9260b9d"),
  ]
  for c in cases {
    let (n, expected) = c
    assert_eq(@rapidhash.to_hex(@rapidhash.rapidhash(buf(n))), expected)
  }
  assert_eq(@rapidhash.to_hex(@rapidhash.rapidhash(b"abc")), "cb475beafa9c0da2")
}

///|
test "seed perturbs the result deterministically" {
  let h0 = @rapidhash.rapidhash(b"abc")
  let hs = @rapidhash.rapidhash(b"abc", seed=0x9E3779B185EBCA87)
  assert_not_eq(h0, hs)
  assert_eq(@rapidhash.rapidhash(b"abc", seed=0x9E3779B185EBCA87), hs)
}
