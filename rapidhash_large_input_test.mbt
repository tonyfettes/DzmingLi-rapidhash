// Known-answer vectors for large inputs, generated from the reference C
// (rapidhash V3, seed 0, clang at /tmp/rapidhash-upstream). Inputs are
// `byte i = (i * 31) & 0xFF`. Sizes beyond 448 exercise multiple iterations
// of the 224-byte unrolled loop; the ≤256-byte vectors in rapidhash_test.mbt
// cover at most one iteration, so these extend coverage to the multi-round
// hot path.

///|
fn ramp(n : Int) -> Bytes {
  Bytes::makei(n, fn(i) { ((i * 31) & 0xFF).to_byte() })
}

///|
test "rapidhash large-input KATs (vs reference C)" {
  let cases : Array[(Int, String)] = [
    (480, "90d595303eba015c"),
    (1024, "c1254e123cbdad27"),
    (65536, "9e6bc0087001597a"),
    (1048576, "ddd1ea56f3843c4f"),
  ]
  for c in cases {
    let (n, expected) = c
    assert_eq(@rapidhash.to_hex(@rapidhash.rapidhash(ramp(n))), expected)
  }
}
