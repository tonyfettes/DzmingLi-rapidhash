// Known-answer vectors copied verbatim from the reference C++ test
// (google/highwayhash, highwayhash_test.cc `kExpected64`). Key is the
// reference `kTestKey`; input of length n is bytes [0,1,…,n-1] (mod 256),
// matching the reference's `in[i]=i` construction.

///|
fn buf(n : Int) -> Bytes {
  Bytes::makei(n, fn(i) { (i % 256).to_byte() })
}

///|
test "HighwayHash-64 known-answer vectors (vs reference C++)" {
  // kTestKey = {0x0706050403020100, 0x0F0E0D0C0B0A0908,
  //             0x1716151413121110, 0x1F1E1D1C1B1A1918}
  let cases : Array[(Int, String)] = [
    (0, "907a56de22c26e53"),
    (1, "7eab43aac7cddd78"),
    (2, "b8d0569ab0b53d62"),
    (3, "5c6befab8a463d80"),
    (4, "f205a46893007eda"),
    (5, "2b8a1668e4a94541"),
    (6, "bd4ccc325befca6f"),
    (7, "4d02ae1738f59482"),
    (8, "e1205108e55f3171"),
    (9, "32d2644ec77a1584"),
    (10, "f6e10acdb103a90b"),
    (11, "c3bbf4615b415c15"),
    (12, "243cc2040063fa9c"),
    (13, "a89a58ce65e641ff"),
    (14, "24b031a348455a23"),
    (15, "40793f86a449f33b"),
    (16, "cfab3489f97eb832"),
    (17, "19fe67d2c8c5c0e2"),
    (18, "04dd90a69c565cc2"),
    (19, "75d9518e2371c504"),
    (20, "38ad9b1141d3dd16"),
    (21, "0264432ccd8a70e0"),
    (22, "a9db5a6288683390"),
    (23, "d7b05492003f028c"),
    (24, "205f615aea59e51e"),
    (25, "eee0c89621052884"),
    (26, "1bfc1a93a7284f4f"),
    (27, "512175b5b70da91d"),
    (28, "f71f8976a0a2c639"),
    (29, "ae093fef1f84e3e7"),
    (30, "22ca92b01161860f"),
    (31, "9fc7007ccf035a68"),
    (32, "a0c964d9ecd580fc"),
    (33, "2c90f73ca03181fc"),
    (34, "185cf84e5691eb9e"),
    (35, "4fc1f5ef2752aa9b"),
    (36, "f5b7391a5e0a33eb"),
    (37, "b9b84b83b4e96c9c"),
    (38, "5e42fe712a5cd9b4"),
    (39, "a150f2f90c3f97dc"),
    (40, "7fa522d75e2d637d"),
    (41, "181ad0cc0dffd32b"),
    (42, "3889ed981e854028"),
    (43, "fb4297e8c586ee2d"),
    (44, "6d064a45bb28059c"),
    (45, "90563609b3ec860c"),
    (46, "7aa4fce94097c666"),
    (47, "1326bac06b911e08"),
    (48, "b926168d2b154f34"),
    (49, "9919848945b1948d"),
    (50, "a2a98fc534825ebe"),
    (51, "e9809095213ef0b6"),
    (52, "582e5483707bc0e9"),
    (53, "086e9414a88a6af5"),
    (54, "ee86b98d20f6743d"),
    (55, "f89b7ff609b1c0a7"),
    (56, "4c7d9cc19e22c3e8"),
    (57, "9a97005024562a6f"),
    (58, "5dd41cf423e6ebef"),
    (59, "df13609c0468e227"),
    (60, "6e0da4f64188155a"),
    (61, "b755ba4b50d7d4a1"),
    (62, "887a3484647479bd"),
    (63, "ab8eebe9bf2139a0"),
    (64, "75542c5d4cd2a6ff"),
  ]
  for c in cases {
    let (n, expected) = c
    let h = @highwayhash.highwayhash64(
      buf(n),
      k0=0x0706050403020100,
      k1=0x0F0E0D0C0B0A0908,
      k2=0x1716151413121110,
      k3=0x1F1E1D1C1B1A1918,
    )
    assert_eq(@highwayhash.to_hex(h), expected)
  }
}
