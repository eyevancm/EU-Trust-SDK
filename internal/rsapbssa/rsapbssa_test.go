package rsapbssa

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"io"
	"math/big"
	"strings"
	"testing"
)

// hexToBytes decodes a hex string (with optional whitespace/newlines) to bytes.
func hexToBytes(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex in test vector: " + err.Error())
	}
	return b
}

func hexToBigInt(s string) *big.Int {
	b := hexToBytes(s)
	return new(big.Int).SetBytes(b)
}

// RFC test vector key pair (shared across all test vectors in the draft).
// Modulus is the product of two safe primes.
var (
	testP = hexToBigInt("dcd90af1be463632c0d5ea555256a20605af3db667475e190e3af12a34a3324c46a3094062c59fb4b249e0ee6afba8bee14e0276d126c99f4784b23009bf6168ff628ac1486e5ae8e23ce4d362889de4df63109cbd90ef93db5ae64372bfe1c55f832766f21e94ea3322eb2182f10a891546536ba907ad74b8d72469bea396f3")
	testQ = hexToBigInt("f8ba5c89bd068f57234a3cf54a1c89d5b4cd0194f2633ca7c60b91a795a56fa8c8686c0e37b1c4498b851e3420d08bea29f71d195cfbd3671c6ddc49cf4c1db5b478231ea9d91377ffa98fe95685fca20ba4623212b2f2def4da5b281ed0100b651f6db32112e4017d831c0da668768afa7141d45bbc279f1e0f8735d74395b3")
	testD = hexToBigInt("4e21356983722aa1adedb084a483401c1127b781aac89eab103e1cfc52215494981d18dd8028566d9d499469c25476358de23821c78a6ae43005e26b394e3051b5ca206aa9968d68cae23b5affd9cbb4cb16d64ac7754b3cdba241b72ad6ddfc000facdb0f0dd03abd4efcfee1730748fcc47b7621182ef8af2eeb7c985349f62ce96ab373d2689baeaea0e28ea7d45f2d605451920ca4ea1f0c08b0f1f6711eaa4b7cca66d58a6b916f9985480f90aca97210685ac7b12d2ec3e30a1c7b97b65a18d38a93189258aa346bf2bc572cd7e7359605c20221b8909d599ed9d38164c9c4abf396f897b9993c1e805e574d704649985b600fa0ced8e5427071d7049d")
	testE = big.NewInt(65537)
	testN = hexToBigInt("d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e2318d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facba9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d75ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb19d6fae9")
)

func testKeyPair() *KeyPair {
	return KeyPairFromComponents(testN, testE, testD, testP, testQ)
}

func testPublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{N: testN, E: int(testE.Int64())}
}

// --- Test: Key pair construction ---

func TestKeyPairFromComponents(t *testing.T) {
	kp := testKeyPair()

	// Verify N = P * Q
	pq := new(big.Int).Mul(kp.P, kp.Q)
	if pq.Cmp(kp.N) != 0 {
		t.Error("N != P * Q")
	}

	// Verify D * E ≡ 1 (mod Phi)
	de := new(big.Int).Mul(kp.D, big.NewInt(int64(kp.E)))
	de.Mod(de, kp.Phi)
	if de.Cmp(big.NewInt(1)) != 0 {
		t.Error("D * E != 1 mod Phi")
	}
}

// --- Test: DerivePublicKey ---

// Test vector 1: msg = "hello world", info = "metadata"
func TestDerivePublicKey_WithMetadata(t *testing.T) {
	pk := testPublicKey()
	info := hexToBytes("6d65746164617461") // "metadata"

	expectedEPrime := hexToBigInt("30581b1adab07ac00a5057e2986f37caaa68ae963ffbc4d36c16ea5f3689d6f00db79a5bee56053adc53c8d0414d4b754b58c7cc4abef99d4f0d0b2e29cbddf746c7d0f4ae2690d82a2757b088820c0d086a40d180b2524687060d768ad5e431732102f4bc3572d97e01dcd6301368f255faae4606399f91fa913a6d699d6ef1")

	derived, err := DerivePublicKey(pk, info)
	if err != nil {
		t.Fatalf("DerivePublicKey error: %v", err)
	}

	if derived.N.Cmp(pk.N) != 0 {
		t.Error("derived public key has different N")
	}

	if derived.E.Cmp(expectedEPrime) != 0 {
		t.Errorf("derived e' mismatch:\n  got  %x\n  want %x",
			derived.E.Bytes(), expectedEPrime.Bytes())
	}
}

// Test vector 2: msg = "hello world", info = "" (empty)
func TestDerivePublicKey_EmptyMetadata(t *testing.T) {
	pk := testPublicKey()
	info := []byte{} // empty metadata

	expectedEPrime := hexToBigInt("2ed579fcdf2d328ebc686c52ccaec247018832acd530a2ac72c0ec2b92db5d6bd578e91b6341c1021142b45b9e6e5bf031f3dd62226ec4a0f9ef99e45dd9ccd60aa60a0c59aac271a8caf9ee68a9d9ff281367dae09d588d3c7bca7f18de48b6981bbc729c4925c65e4b2a7f054facbb7e5fc6e4c6c10110c62ef0b94eec397b")

	derived, err := DerivePublicKey(pk, info)
	if err != nil {
		t.Fatalf("DerivePublicKey error: %v", err)
	}

	if derived.E.Cmp(expectedEPrime) != 0 {
		t.Errorf("derived e' mismatch:\n  got  %x\n  want %x",
			derived.E.Bytes(), expectedEPrime.Bytes())
	}
}

// --- Test: Full protocol round-trip (test vector 1) ---
// msg = "hello world", info = "metadata"
// PSS salt and blinding factor r are fixed from the IETF draft Appendix B.
func TestProtocolRoundTrip_Vector1(t *testing.T) {
	kp := testKeyPair()
	pk := kp.PublicKey()

	msg := hexToBytes("68656c6c6f20776f726c64") // "hello world"
	info := hexToBytes("6d65746164617461")       // "metadata"

	// PSS salt from draft-amjad-cfrg-partially-blind-rsa-01 Appendix B vector 1
	pssSalt := hexToBytes("648ea74482fbab69876817ee3c2055a6921a458648c802c09a23f8825b259724e41c960ef29febe16a04e120c8b1cc1a")
	blind := hexToBigInt("d55491221c9a9ce5687b84669880abbc4db57c8f82864a450a5bf7c3f0902884fa418c74bf663f3bfcff74a4792356f3ce052f128b084f8b028cf43253327514f4b38430c69f19f155634429803badd1f6849d8603882eb9b648b697cb2f2c4069b504562e19bb9f1cf99da47c198c2ae04f4bd3add78025e80f146edce48dc3e9dc0ba3ee14bc97489050e26dc8935f3ecfcaea07c9c1a3d8e41be1e49dc8aa171ac4cec9d1cddd8066b13767901dcb339e2cce40d11f5cff6c870012bca49109ce6e81e165d3831531cbf8503f3cfde68340789979cba96602e70613a13869aff57f2170e31ebe85564e3f026d8cd1835e59144fb8c008391c55d2fb1a5488")

	expectedBlindedMsg := hexToBytes("cfd613e27b8eb15ee0b1df0e1bdda7809a61a29e9b6e9f3ec7c345353437638e85593a7309467e36396b0515686fe87330b312b6f89df26dc1cc88dd222186ca0bfd4ffa0fd16a9749175f3255425eb299e1807b76235befa57b28f50db02f5df76cf2f8bcb55c3e2d39d8c4b9a0439e71c5362f35f3db768a5865b864fdf979bc48d4a29ae9e7c2ea259dc557503e2938b9c3080974bd86ad8b0daaf1d103c31549dcf767798079f88833b579424ed5b3d700162136459dc29733256f18ceb74ccf0bc542db8829ca5e0346ad3fe36654715a3686ceb69f73540efd20530a59062c13880827607c68d00993b47ad6ba017b95dfc52e567c4bf65135072b12a4")
	expectedBlindSig := hexToBytes("ca7d4fd21085de92b514fbe423c5745680cace6ddfa864a9bd97d29f3454d5d475c6c1c7d45f5da2b7b6c3b3bc68978bb83929317da25f491fee86ef7e051e7195f3558679b18d6cd3788ac989a3960429ad0b7086945e8c4d38a1b3b52a3903381d9b1bf9f3d48f75d9bb7a808d37c7ecebfd2fea5e89df59d4014a1a149d5faecfe287a3e9557ef153299d49a4918a6dbdef3e086eeb264c0c3621bcd73367195ae9b14e67597eaa9e3796616e30e264dc8c86897ae8a6336ed2cd93416c589a058211688cf35edbd22d16e31c28ff4a5c20f1627d09a71c71af372edc18d2d7a6e39df9365fe58a34605fa1d9dc53efd5a262de849fb083429e20586e210e")
	expectedSig := hexToBytes("cdc6243cd9092a8db6175b346912f3cc55e0cf3e842b4582802358dddf6f61decc37b7a9ded0a108e0c857c12a8541985a6efad3d17f7f6cce3b5ee20016e5c36c7d552c8e8ff6b5f3f7b4ed60d62eaec7fc11e4077d7e67fc6618ee092e2005964b8cf394e3e409f331dca20683f5a631b91cae0e5e2aa89eeef4504d24b45127abdb3a79f9c71d2f95e4d16c9db0e7571a7f524d2f64438dfb32001c00965ff7a7429ce7d26136a36ebe14644559d3cefc477859dcd6908053907b325a34aaf654b376fade40df4016ecb3f5e1c89fe3ec500a04dfe5c8a56cad5b086047d2f963ca73848e74cf24bb8bf1720cc9de4c78c64449e8af3e7cddb0dab1821998")

	// Step 1: Client blinds message with deterministic PSS salt + known r
	rng := io.MultiReader(bytes.NewReader(pssSalt), bytes.NewReader(nil))
	blindedMsg, inv, err := Blind(rng, pk, msg, info, blind)
	if err != nil {
		t.Fatalf("Blind error: %v", err)
	}

	if !bytes.Equal(blindedMsg.BlindedMsg, expectedBlindedMsg) {
		t.Errorf("blinded message mismatch:\n  got  %x\n  want %x",
			blindedMsg.BlindedMsg, expectedBlindedMsg)
	}

	// Step 2: Server signs blinded message
	blindSig, err := BlindSign(kp, blindedMsg.BlindedMsg, info)
	if err != nil {
		t.Fatalf("BlindSign error: %v", err)
	}

	if !bytes.Equal(blindSig.BlindSig, expectedBlindSig) {
		t.Errorf("blind signature mismatch:\n  got  %x\n  want %x",
			blindSig.BlindSig, expectedBlindSig)
	}

	// Step 3: Client finalizes (unblinds + verifies)
	sig, err := Finalize(pk, msg, info, blindSig, inv)
	if err != nil {
		t.Fatalf("Finalize error: %v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Errorf("final signature mismatch:\n  got  %x\n  want %x",
			sig, expectedSig)
	}

	// Step 4: Independent verification
	if err := Verify(pk, msg, info, sig); err != nil {
		t.Fatalf("Verify error: %v", err)
	}
}

// Test vector 2: msg = "hello world", info = "" (empty metadata)
func TestProtocolRoundTrip_Vector2_EmptyMetadata(t *testing.T) {
	kp := testKeyPair()
	pk := kp.PublicKey()

	msg := hexToBytes("68656c6c6f20776f726c64") // "hello world"
	info := []byte{}

	// PSS salt from draft-amjad-cfrg-partially-blind-rsa-01 Appendix B vector 2
	pssSalt := hexToBytes("134520fb9ae6076594b4488fa31cae4e8e3efaca5ae4377bd586aac58e90f8925826b4b4fff2e21fdb933c4fbb6467a2")
	blind := hexToBigInt("532103acf62670e3176eb1cfee7c2c46c7986704b869387924c33e83588c7cac67882570aede836b51b44a565c872a91bbf4f0f8396019113ef382963d3a51b91429993e821217d3e85b2253e0daa0e9cfc440c37a37707f7aed383d98b3150f21e1146c58c28d4a49046b8e97f834e4cb95e5483dfc42eaa17bdce9476317f710b7488cc06cf61a1c449faa1d34119f2c3cd6ead79f9de14358b1c750bf2c312fcbba3c511341fd4952ba2fcd486a9e81fd829e47cd8a0ac0273d7594c69eb4aebfaec3c59aa1a016582410d9f4be14dac4b1a66f61eeb3e108af3868e410f77436765ba1df7c9a5cf37d8ec3dced6f5689da9703618a5cc7bf6d60f7b4209c")

	expectedSig := hexToBytes("a7ace477c1f416a40e93ddf8a454f9c626b33c5a20067d81bdfef7b88bc15de2b04624478b2134b4b23d91285d72ca4eb9c6c911cd7be2437f4e3b24426bce1a1cb52e2c8a4d13f7fd5c9b0f943b92b8bbcba805b847a0ea549dbc249f2e812bf03dd6b2588c8af22bf8b6bba56ffd8d2872b2f0ebd42ac8bd8339e5e63806199deec3cf392c078f66e72d9be817787d4832c45c1f192465d87f6f6c333ce1e8c5641c7069280443d2227f6f28ff2045acdc368f2f94c38a3c909591a27c93e1778630aeeeb623805f37c575213091f096be14ffa739ee55b3f264450210a4b2e61a9b12141ca36dd45e3b81116fc286e469b707864b017634b8a409ae99c9f1")

	rng := bytes.NewReader(pssSalt)
	blindedMsg, inv, err := Blind(rng, pk, msg, info, blind)
	if err != nil {
		t.Fatalf("Blind error: %v", err)
	}

	blindSig, err := BlindSign(kp, blindedMsg.BlindedMsg, info)
	if err != nil {
		t.Fatalf("BlindSign error: %v", err)
	}

	sig, err := Finalize(pk, msg, info, blindSig, inv)
	if err != nil {
		t.Fatalf("Finalize error: %v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Errorf("final signature mismatch:\n  got  %x\n  want %x",
			sig, expectedSig)
	}

	if err := Verify(pk, msg, info, sig); err != nil {
		t.Fatalf("Verify error: %v", err)
	}
}

// Test vector 3: msg = "" (empty), info = "metadata"
func TestProtocolRoundTrip_Vector3_EmptyMessage(t *testing.T) {
	kp := testKeyPair()
	pk := kp.PublicKey()

	msg := []byte{}
	info := hexToBytes("6d65746164617461") // "metadata"

	// PSS salt from draft-amjad-cfrg-partially-blind-rsa-01 Appendix B vector 3
	pssSalt := hexToBytes("1ade5e965d1946a69dc495e78c8524910094f08405471664d4898fa3612bf03fd03b3ae8140a737cb13e223e35219b58")
	blind := hexToBigInt("6e1de89fc58417836aa76fefe4876b8b311af2eb94a8226d579627317148551d90b6f9db614b590e7f66f34644a2f6a3568ec78852b7f45876f576a7ee60c19bb0fbbdf1c85d7b36cf7bdf80fb925830c07285efae69e0c019d8d99fd5c620f83361c9411541fddf4bfe27e73f756bf594742a8253119d134e1ad67f0222859c4ab243868bb23a6468c01ead9a617657056685f19fcd423b9e916c5e3e3b21f92d0e12667d695084a42ae97a548d5982a51b67dd09c188c051d20236e24b231e80a96449390e9032bad350645f5d4a162ddf3d61506ef6737b4f9fe6064a1d2fafc7849e5039a98ebf14a800dc2423fccc1293f28a2c66ec22983cab922c1cc6")

	expectedSig := hexToBytes("02bc0f2728e2b8cd1c1b9873d4b7f5a62017430398165a6f8964842eaa19c1de292207b74dc25ee0aa90493216d3fbf8e1b2947fd64335277b34767f987c482c69262967c8a8aaf180a4006f456c804cdc7b92d956a351ad89703cc76f69ed45f24d68e1ae0361479e0f6faf10c3b1582de2dcd2af432d57c0c89c8efb1cf3ac5f991fe9c4f0ad24473939b053674a2582518b4bd57da109f4f37bc91a2f806e82bb2b80d486d0694e663992c9517c946607b978f557bbb769d4cd836d693c77da480cd89b916e5e4190f317711d9c7e64528a314a14bf0b9256f4c60e9ddb550583c21755ab882bdfdf22dc840249389b1e0a2189f58e19b41c5f313cddce29")

	rng := bytes.NewReader(pssSalt)
	blindedMsg, inv, err := Blind(rng, pk, msg, info, blind)
	if err != nil {
		t.Fatalf("Blind error: %v", err)
	}

	blindSig, err := BlindSign(kp, blindedMsg.BlindedMsg, info)
	if err != nil {
		t.Fatalf("BlindSign error: %v", err)
	}

	sig, err := Finalize(pk, msg, info, blindSig, inv)
	if err != nil {
		t.Fatalf("Finalize error: %v", err)
	}

	if !bytes.Equal(sig, expectedSig) {
		t.Errorf("final signature mismatch:\n  got  %x\n  want %x",
			sig, expectedSig)
	}

	if err := Verify(pk, msg, info, sig); err != nil {
		t.Fatalf("Verify error: %v", err)
	}
}

// --- Negative tests ---

func TestVerify_WrongMetadata(t *testing.T) {
	kp := testKeyPair()
	pk := kp.PublicKey()
	msg := []byte("hello world")
	info := []byte("metadata")
	otherInfo := []byte("other")

	blindedMsg, inv, err := Blind(nil, pk, msg, info, nil)
	if err != nil {
		t.Fatalf("Blind error: %v", err)
	}
	blindSig, err := BlindSign(kp, blindedMsg.BlindedMsg, info)
	if err != nil {
		t.Fatalf("BlindSign error: %v", err)
	}
	sig, err := Finalize(pk, msg, info, blindSig, inv)
	if err != nil {
		t.Fatalf("Finalize error: %v", err)
	}

	// Signature valid under info="metadata" must NOT verify under info="other"
	if err := Verify(pk, msg, otherInfo, sig); err == nil {
		t.Error("expected verification failure with wrong metadata, got nil")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	kp := testKeyPair()
	pk := kp.PublicKey()
	msg := []byte("hello world")
	info := []byte("metadata")

	blindedMsg, inv, err := Blind(nil, pk, msg, info, nil)
	if err != nil {
		t.Fatalf("Blind error: %v", err)
	}
	blindSig, err := BlindSign(kp, blindedMsg.BlindedMsg, info)
	if err != nil {
		t.Fatalf("BlindSign error: %v", err)
	}
	sig, err := Finalize(pk, msg, info, blindSig, inv)
	if err != nil {
		t.Fatalf("Finalize error: %v", err)
	}

	// Flip one bit in the signature
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)/2] ^= 0x01

	if err := Verify(pk, msg, info, tampered); err == nil {
		t.Error("expected verification failure with tampered signature, got nil")
	}
}
