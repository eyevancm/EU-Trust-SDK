// Package rsapbssa implements RSA Partially Blind Signatures with Appendix
// as specified in draft-amjad-cfrg-partially-blind-rsa-01.
//
// This is Privacy Pass token type 3 (RFC 9578): the issuer and client agree
// on public metadata that is cryptographically bound to the token, but the
// issuer cannot link issuance to redemption.
//
// Key requirement: RSA modulus must be the product of two safe primes.
// Standard RSA key generation is NOT sufficient.
package rsapbssa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// Variant identifies the RSAPBSSA parameter set.
type Variant int

const (
	// SHA384PSSRandomized uses SHA-384, MGF1-SHA384, 48-byte salt,
	// and the randomized preparation function. RECOMMENDED by the spec.
	SHA384PSSRandomized Variant = iota
)

const (
	hashLen = 48 // SHA-384 output length in bytes
	saltLen = 48 // PSS salt length for SHA384PSSRandomized
)

// Errors
var (
	ErrMessageTooLong = errors.New("rsapbssa: message too long")
	ErrEncodingError  = errors.New("rsapbssa: encoding error")
	ErrBlindingError  = errors.New("rsapbssa: blinding error")
	ErrInvalidInput   = errors.New("rsapbssa: invalid input")
	ErrSigningFailure = errors.New("rsapbssa: signing failure")
	ErrInvalidSig     = errors.New("rsapbssa: invalid signature")
	ErrBadKeySize     = errors.New("rsapbssa: key not product of safe primes")
)

// KeyPair holds an RSA key pair where the modulus is the product of
// two safe primes, as required by RSAPBSSA.
type KeyPair struct {
	// N = p * q where p and q are safe primes (p = 2p' + 1, q = 2q' + 1).
	N *big.Int
	E int // Public exponent (65537)
	D *big.Int
	P *big.Int
	Q *big.Int

	// Phi = (p-1) * (q-1), precomputed for key derivation.
	Phi *big.Int
}

// DerivedPublicKey holds a metadata-specific RSA public key.
// The derived exponent E is ~half the modulus size and cannot be stored
// in rsa.PublicKey.E (which is int). Both blinding and verification use
// this type internally.
type DerivedPublicKey struct {
	N *big.Int
	E *big.Int
}

// BlindedMessage is the output of the Blind step (client → server).
type BlindedMessage struct {
	// BlindedMsg is the blinded, PSS-encoded message.
	BlindedMsg []byte
}

// BlindingInverse is the client's secret inverse used in Finalize.
type BlindingInverse struct {
	inv *big.Int
}

// BlindSignature is the output of BlindSign (server → client).
type BlindSignature struct {
	BlindSig []byte
}

// --- Key Generation ---

// GenerateKey generates an RSA key pair with a modulus that is the product
// of two safe primes, as required by RSAPBSSA. bits is the modulus size.
//
// WARNING: This is SLOW — safe prime generation requires many primality tests.
// Expect 2-4 hours for 2048-bit keys. Call once at setup, save to disk.
func GenerateKey(bits int) (*KeyPair, error) {
	primeBits := bits/2 - 1
	for {
		// Generate safe prime p = 2p' + 1
		p, err := generateSafePrime(primeBits)
		if err != nil {
			return nil, err
		}
		// Generate safe prime q = 2q' + 1
		q, err := generateSafePrime(primeBits)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}

		pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
		qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
		phi := new(big.Int).Mul(pMinus1, qMinus1)

		e := big.NewInt(65537)
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}

		return &KeyPair{N: n, E: int(e.Int64()), D: d, P: p, Q: q, Phi: phi}, nil
	}
}

func generateSafePrime(bits int) (*big.Int, error) {
	for {
		// Generate a prime p' of the given bit size
		pPrime, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		// p = 2p' + 1
		p := new(big.Int).Mul(pPrime, big.NewInt(2))
		p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

// KeyPairFromComponents constructs a KeyPair from raw components.
// Used for testing with known values from RFC test vectors.
func KeyPairFromComponents(n, e, d, p, q *big.Int) *KeyPair {
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	return &KeyPair{
		N:   n,
		E:   int(e.Int64()),
		D:   d,
		P:   p,
		Q:   q,
		Phi: phi,
	}
}

// PublicKey returns the standard library RSA public key.
func (kp *KeyPair) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{N: kp.N, E: kp.E}
}

// --- Public Key Derivation ---

// DerivePublicKey derives a metadata-specific public key from the base
// public key and the metadata bytes, per Section 4.6 of the draft.
//
// The derived exponent e' is derived via HKDF-SHA384 and is typically
// ~half the modulus size — too large for rsa.PublicKey.E.
func DerivePublicKey(pk *rsa.PublicKey, info []byte) (*DerivedPublicKey, error) {
	modulusLen := (pk.N.BitLen() + 7) / 8
	lambdaLen := modulusLen / 2
	hkdfLen := lambdaLen + 16

	// IKM = "key" || info || 0x00
	ikm := make([]byte, 0, 3+len(info)+1)
	ikm = append(ikm, "key"...)
	ikm = append(ikm, info...)
	ikm = append(ikm, 0x00)

	// Salt = I2OSP(n, modulusLen)
	salt := make([]byte, modulusLen)
	pk.N.FillBytes(salt)

	// HKDF-SHA384 with label "PBRSA"
	reader := hkdf.New(sha512.New384, ikm, salt, []byte("PBRSA"))
	expanded := make([]byte, hkdfLen)
	if _, err := io.ReadFull(reader, expanded); err != nil {
		return nil, err
	}

	// Clear two most significant bits, set LSB (ensure odd)
	expanded[0] &= 0x3F
	expanded[lambdaLen-1] |= 0x01

	ePrime := new(big.Int).SetBytes(expanded[:lambdaLen])

	return &DerivedPublicKey{N: pk.N, E: ePrime}, nil
}

// DeriveKeyPair derives the metadata-specific private and public exponents.
// Returns (e', d') where d' = e'^(-1) mod phi(N).
func DeriveKeyPair(kp *KeyPair, info []byte) (ePrime, dPrime *big.Int, err error) {
	derived, err := DerivePublicKey(kp.PublicKey(), info)
	if err != nil {
		return nil, nil, err
	}
	ePrime = derived.E
	dPrime = new(big.Int).ModInverse(ePrime, kp.Phi)
	if dPrime == nil {
		return nil, nil, errors.New("rsapbssa: derived e' is not coprime with phi(N)")
	}
	return ePrime, dPrime, nil
}

// --- Protocol Functions ---

// Blind encodes and blinds a message with the given public key and metadata.
// Returns the blinded message (to send to the server) and the blinding
// inverse (kept secret by the client for Finalize).
//
// rng is used for PSS salt generation. Pass nil to use crypto/rand.Reader.
// randomBlind, if non-nil, is used as the blinding factor r (for testing).
func Blind(rng io.Reader, pk *rsa.PublicKey, msg, info []byte, randomBlind *big.Int) (BlindedMessage, BlindingInverse, error) {
	if rng == nil {
		rng = rand.Reader
	}

	modulusLen := (pk.N.BitLen() + 7) / 8
	emBits := pk.N.BitLen() - 1

	// msg' = "msg" || I2OSP(len(info), 4) || info || msg
	msgPrime := buildMsgPrime(msg, info)

	// EMSA-PSS-ENCODE
	em, err := pssEncode(rng, msgPrime, emBits)
	if err != nil {
		return BlindedMessage{}, BlindingInverse{}, err
	}
	m := new(big.Int).SetBytes(em)

	// Use provided blinding factor or generate a random one
	r := randomBlind
	if r == nil {
		r, err = rand.Int(rand.Reader, pk.N)
		if err != nil {
			return BlindedMessage{}, BlindingInverse{}, err
		}
	}

	inv := new(big.Int).ModInverse(r, pk.N)
	if inv == nil {
		return BlindedMessage{}, BlindingInverse{}, ErrBlindingError
	}

	// Derive metadata-specific public key
	derived, err := DerivePublicKey(pk, info)
	if err != nil {
		return BlindedMessage{}, BlindingInverse{}, err
	}

	// x = r^e' mod n, z = m * x mod n
	x := new(big.Int).Exp(r, derived.E, pk.N)
	z := new(big.Int).Mul(m, x)
	z.Mod(z, pk.N)

	blindedMsgBytes := make([]byte, modulusLen)
	z.FillBytes(blindedMsgBytes)

	return BlindedMessage{BlindedMsg: blindedMsgBytes}, BlindingInverse{inv: inv}, nil
}

// BlindSign performs the RSA signing operation on a blinded message
// using the metadata-derived private key, per Section 4.3.
func BlindSign(kp *KeyPair, blindedMsg, info []byte) (BlindSignature, error) {
	modulusLen := (kp.N.BitLen() + 7) / 8

	m := new(big.Int).SetBytes(blindedMsg)
	if m.Cmp(kp.N) >= 0 {
		return BlindSignature{}, ErrInvalidInput
	}

	ePrime, dPrime, err := DeriveKeyPair(kp, info)
	if err != nil {
		return BlindSignature{}, err
	}

	// s = m^d' mod n
	s := new(big.Int).Exp(m, dPrime, kp.N)

	// Verify: s^e' mod n must equal m (per spec Section 4.3)
	mCheck := new(big.Int).Exp(s, ePrime, kp.N)
	if mCheck.Cmp(m) != 0 {
		return BlindSignature{}, ErrSigningFailure
	}

	blindSigBytes := make([]byte, modulusLen)
	s.FillBytes(blindSigBytes)

	return BlindSignature{BlindSig: blindSigBytes}, nil
}

// Finalize unblinds the server's blind signature, verifies correctness,
// and returns the final signature, per Section 4.4.
func Finalize(pk *rsa.PublicKey, msg, info []byte, blindSig BlindSignature, inv BlindingInverse) ([]byte, error) {
	modulusLen := (pk.N.BitLen() + 7) / 8

	if len(blindSig.BlindSig) != modulusLen {
		return nil, ErrInvalidInput
	}

	z := new(big.Int).SetBytes(blindSig.BlindSig)

	// s = z * inv mod n (unblind)
	s := new(big.Int).Mul(z, inv.inv)
	s.Mod(s, pk.N)

	sig := make([]byte, modulusLen)
	s.FillBytes(sig)

	// Verify the unblinded signature
	if err := Verify(pk, msg, info, sig); err != nil {
		return nil, ErrInvalidSig
	}

	return sig, nil
}

// Verify checks a signature against a message, metadata, and public key,
// per Section 4.5.
func Verify(pk *rsa.PublicKey, msg, info, sig []byte) error {
	modulusLen := (pk.N.BitLen() + 7) / 8
	emBits := pk.N.BitLen() - 1

	if len(sig) != modulusLen {
		return ErrInvalidSig
	}

	// Derive metadata-specific public key
	derived, err := DerivePublicKey(pk, info)
	if err != nil {
		return err
	}

	s := new(big.Int).SetBytes(sig)
	if s.Cmp(pk.N) >= 0 {
		return ErrInvalidSig
	}

	// m = s^e' mod n (RSA "encrypt" with derived public key)
	m := new(big.Int).Exp(s, derived.E, pk.N)

	em := make([]byte, modulusLen)
	m.FillBytes(em)

	// msg' = "msg" || I2OSP(len(info), 4) || info || msg
	msgPrime := buildMsgPrime(msg, info)

	return pssVerify(msgPrime, em, emBits)
}

// --- PSS Encoding / Decoding (RFC 8017 Section 9.1) ---

// pssEncode implements EMSA-PSS-ENCODE with SHA-384, MGF1-SHA384, sLen=48.
// rng provides the PSS salt bytes.
func pssEncode(rng io.Reader, msg []byte, emBits int) ([]byte, error) {
	emLen := (emBits + 7) / 8

	if emLen < hashLen+saltLen+2 {
		return nil, ErrEncodingError
	}

	mHash := sha384(msg)

	// Generate PSS salt
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rng, salt); err != nil {
		return nil, err
	}

	// M' = 0x00^8 || mHash || salt
	mPrime := make([]byte, 8+hashLen+saltLen)
	copy(mPrime[8:], mHash)
	copy(mPrime[8+hashLen:], salt)
	H := sha384(mPrime)

	// DB = PS || 0x01 || salt  (PS = emLen - saltLen - hashLen - 2 zero bytes)
	dbLen := emLen - hashLen - 1
	psLen := dbLen - saltLen - 1
	db := make([]byte, dbLen)
	db[psLen] = 0x01
	copy(db[psLen+1:], salt)

	// maskedDB = DB XOR MGF1(H, dbLen)
	xorBytes(db, mgf1SHA384(H, dbLen))

	// Clear leftmost 8*emLen - emBits bits of maskedDB[0]
	topBits := uint(8*emLen - emBits)
	db[0] &= 0xFF >> topBits

	// EM = maskedDB || H || 0xbc
	em := make([]byte, emLen)
	copy(em, db)
	copy(em[dbLen:], H)
	em[emLen-1] = 0xbc

	return em, nil
}

// pssVerify implements EMSA-PSS-VERIFY with SHA-384, MGF1-SHA384, sLen=48.
func pssVerify(msg, em []byte, emBits int) error {
	emLen := (emBits + 7) / 8

	if len(em) != emLen {
		return ErrInvalidSig
	}
	if emLen < hashLen+saltLen+2 {
		return ErrInvalidSig
	}
	if em[emLen-1] != 0xbc {
		return ErrInvalidSig
	}

	mHash := sha384(msg)

	dbLen := emLen - hashLen - 1
	maskedDB := em[:dbLen]
	H := em[dbLen : dbLen+hashLen]

	// Check top bits are zero
	topBits := uint(8*emLen - emBits)
	if maskedDB[0]&(0xFF<<(8-topBits)) != 0 {
		return ErrInvalidSig
	}

	// DB = maskedDB XOR MGF1(H, dbLen)
	db := make([]byte, dbLen)
	copy(db, maskedDB)
	xorBytes(db, mgf1SHA384(H, dbLen))
	db[0] &= 0xFF >> topBits

	// Verify PS || 0x01 structure
	psLen := dbLen - saltLen - 1
	for i := 0; i < psLen; i++ {
		if db[i] != 0x00 {
			return ErrInvalidSig
		}
	}
	if db[psLen] != 0x01 {
		return ErrInvalidSig
	}

	salt := db[psLen+1:]

	// M' = 0x00^8 || mHash || salt
	mPrime := make([]byte, 8+hashLen+saltLen)
	copy(mPrime[8:], mHash)
	copy(mPrime[8+hashLen:], salt)
	HPrime := sha384(mPrime)

	if subtle.ConstantTimeCompare(H, HPrime) != 1 {
		return ErrInvalidSig
	}
	return nil
}

// --- Helpers ---

func sha384(data []byte) []byte {
	h := sha512.New384()
	h.Write(data)
	return h.Sum(nil)
}

// mgf1SHA384 implements MGF1 with SHA-384 (RFC 8017 Appendix B.2.1).
func mgf1SHA384(seed []byte, length int) []byte {
	out := make([]byte, length)
	done := 0
	var counter [4]byte
	for i := 0; done < length; i++ {
		binary.BigEndian.PutUint32(counter[:], uint32(i))
		h := sha512.New384()
		h.Write(seed)
		h.Write(counter[:])
		chunk := h.Sum(nil)
		n := copy(out[done:], chunk)
		done += n
	}
	return out
}

func xorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// buildMsgPrime constructs msg' = "msg" || I2OSP(len(info), 4) || info || msg
// as used in Blind, Finalize, and Verify.
func buildMsgPrime(msg, info []byte) []byte {
	infoLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(infoLenBytes, uint32(len(info)))

	result := make([]byte, 0, 3+4+len(info)+len(msg))
	result = append(result, "msg"...)
	result = append(result, infoLenBytes...)
	result = append(result, info...)
	result = append(result, msg...)
	return result
}
