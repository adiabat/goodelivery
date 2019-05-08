package bip38

import (
	"crypto/aes"
	"fmt"
	"math/big"

	"github.com/mit-dci/lit/btcutil"
	"github.com/mit-dci/lit/btcutil/base58"
	"github.com/mit-dci/lit/btcutil/chaincfg/chainhash"
	"github.com/mit-dci/lit/coinparam"
	"github.com/mit-dci/lit/crypto/koblitz"
	"golang.org/x/crypto/scrypt"
)

// BIP38Key 's are broken into 3 sections.
// The payload is further broken up depending on flag bits.
type BIP38Key struct {
	Flag     byte
	CheckSum [4]byte
	Payload  [32]byte
}

// Bytes turns a BIP38 key into a byte slice.
// Can be fed directly into a base58 encode
func (k BIP38Key) Bytes() []byte {
	b := make([]byte, 39)
	b[0] = byte(0x01)
	b[1] = byte(0x42)
	b[2] = k.Flag
	copy(b[3:], k.CheckSum[:])
	copy(b[7:], k.Payload[:])
	return b
}

// Validate checks out a bip38 key
func Validate(bstring string) error {
	decoded, ver, err := base58.CheckDecode(bstring)
	if err != nil {
		return err
	}
	if ver != 0x01 {
		return fmt.Errorf("got first byte %x (expect 0x01)", ver)
	}
	if len(decoded) != 38 {
		return fmt.Errorf("got %d byte BIP38 key (expect 38)", len(decoded))
	}
	return nil
}

// Encrypt38 takes a private key and passphrase, and returns the encoded
// and encrypted private key.
// Only does non-EC, because it makes more sense.
func Encrypt38(k *koblitz.PrivateKey,
	compr bool, pass []byte, param *coinparam.Params) (string, error) {

	bkey := new(BIP38Key)
	var pubBytes []byte
	if compr {
		pubBytes = k.PubKey().SerializeCompressed()
	} else {
		pubBytes = k.PubKey().SerializeUncompressed()
	}
	// get address from private key and network parameters
	adr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubBytes), param)
	if err != nil {
		return "", err
	}

	// double hash the ASCII address, that's right...
	// guess this is to distinguish between altcoins
	adrHash := chainhash.DoubleHashH([]byte(adr.String()))
	// e0 for compressed, c0 for uncompressed
	if compr {
		bkey.Flag = 0xe0
	} else {
		bkey.Flag = 0xc0
	}

	copy(bkey.CheckSum[:], adrHash[:4])

	derivKey, err := scrypt.Key(pass, bkey.CheckSum[:], 16384, 8, 8, 64)
	if err != nil {
		return "", err
	}

	var msg, xormix, aesKey [32]byte
	copy(msg[:], k.D.Bytes())
	copy(xormix[:], derivKey[:32])
	copy(aesKey[:], derivKey[32:])

	bkey.Payload = weirdAESEnc(msg, xormix, aesKey)

	keyBytes := bkey.Bytes()
	// using checkEncode to overwrite the first byte.
	// not sure how altcoins are supposed to work here.
	str := base58.CheckEncode(keyBytes[1:], 0x01)
	return str, nil
}

// Decrypt38 takes an encrypted private key and passphrase, and returns the
// decrypted private key.
func Decrypt38(decoded, pass []byte,
	param *coinparam.Params) (*koblitz.PrivateKey, bool, error) {

	var compr bool
	var privArr [32]byte

	bkey := new(BIP38Key)

	bkey.Flag = decoded[1]
	copy(bkey.CheckSum[:], decoded[2:6])
	copy(bkey.Payload[:], decoded[6:])

	if bkey.Flag&0xc0 != 0xc0 {
		privArr = decryptEC(bkey, pass)
	} else {
		privArr = decryptNoEC(bkey, pass)
	}

	priv, pub := koblitz.PrivKeyFromBytes(koblitz.S256(), privArr[:])

	// we have the private key, but it could be wrong.
	// check the address and see if this corresponds to the 4 byte
	// checksum
	var pubBytes []byte

	if bkey.Flag&0x20 != 0 {
		compr = true
	}
	// flag byte indicates compressed (good) or uncompressed (bad) pubkey
	if compr {
		pubBytes = pub.SerializeCompressed()
	} else {
		pubBytes = pub.SerializeUncompressed()
	}

	// generate the address
	adr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubBytes), param)
	if err != nil {
		return nil, compr, err
	}

	// double-hash the *ASCII* string of the address
	adrHash := chainhash.DoubleHashH([]byte(adr.String()))

	// checksum is first 4 bytes of that double-hash
	var resultCheckSum [4]byte
	// make sure checksums match
	copy(resultCheckSum[:], adrHash[:4])
	if resultCheckSum != bkey.CheckSum {
		return nil, compr, fmt.Errorf("decryption checksum error, bad passphrase?")
	}

	return priv, compr, nil
}

// (relatively) straightforward
func decryptNoEC(bk *BIP38Key, pass []byte) [32]byte {
	// the first set of scrypt params
	derivKey, _ := scrypt.Key(pass, bk.CheckSum[:], 16384, 8, 8, 64)
	// only errors if params are wrong, so ignore here

	var xormix, aesKey [32]byte
	copy(xormix[:], derivKey[:32])
	copy(aesKey[:], derivKey[32:])

	return weirdAESDec(bk.Payload, xormix, aesKey)
}

// doesn't support "lot codes / sequence", just the EC mult stuff.
// In this case, theres a bunch of wacky stuff going on:
// The first 8 bytes of the string are a salt, which, with the passphrase
// via a KDF, generate a scalar.  With the scalar you make a point,
// then feed the serialized point into another KDF.
// The second KDF takes that point and the same salt, and returns
// 64 bytes, which are used to decrypt the rest of the initial string (the
// other 24 bytes).
func decryptEC(bk *BIP38Key, pass []byte) [32]byte {
	var privArr [32]byte
	if bk.Flag&0x04 != 0 {
		fmt.Printf("Lot codes not supported\n")
		return privArr
	}

	// ownersalt is the first 8 payload bytes.
	var ownersalt [8]byte
	copy(ownersalt[:], bk.Payload[:8])

	// a 2nd, almost the same, set of parameters for scrypt.
	passScalar, _ := scrypt.Key(pass, ownersalt[:], 16384, 8, 8, 32)
	// ignore scrypt errors; only errors because of params, which are OK here.

	passPointBytes := privToPubBytes(passScalar)
	quickSalt := append(bk.CheckSum[:], ownersalt[:]...)

	// a 3rd, completely different set of scrypt params.
	quickKey, _ := scrypt.Key(passPointBytes, quickSalt, 1024, 1, 1, 64)

	var xormix, aesKey [32]byte
	var ctext24 [24]byte

	// get all arrays in the right place
	copy(xormix[:], quickKey[:32])
	copy(aesKey[:], quickKey[32:])
	copy(ctext24[:], bk.Payload[8:])

	// CFB AES decrypt with those arrays
	seedB := superWeirdAESDec(ctext24, xormix, aesKey)
	// "factor B" is the double hash of this decrypted seed
	factorB := chainhash.DoubleHashB(seedB[:])

	// multiply the password scalar and the hashed factor B
	copy(privArr[:], bigMult(passScalar, factorB))

	return privArr
}

// turns a private key (bytes) into a serialized public key (bytes)
func privToPubBytes(b []byte) []byte {
	// make a new pubkey
	k := new(koblitz.PublicKey)
	// b is the private key
	k.X, k.Y = koblitz.S256().ScalarBaseMult(b)
	// return compressed
	return k.SerializeCompressed()
}

// multiply two bigInts, modulo the curve modulus
func bigMult(a, b []byte) []byte {
	// turn byte slices a and b into bigints
	bigA := new(big.Int).SetBytes(a)
	bigB := new(big.Int).SetBytes(b)
	// a = a*b
	bigA.Mul(bigA, bigB)
	// a = a mod n
	bigA.Mod(bigA, koblitz.S256().N)
	return bigA.Bytes()
}

// bespoke artisial aes encryption function.
func weirdAESEnc(msg, xormix, key [32]byte) (result [32]byte) {
	c, _ := aes.NewCipher(key[:])

	// plaintext gets xored with the xormix
	for i, _ := range xormix {
		msg[i] ^= xormix[i]
	}

	// encrypt in 2 iterations the xormix with the key.
	c.Encrypt(result[:16], msg[:16])
	c.Encrypt(result[16:], msg[16:])

	return
}

// heirloom indigenous aes decrypt function.
func weirdAESDec(ctext, xormix, key [32]byte) (result [32]byte) {
	c, _ := aes.NewCipher(key[:])
	// decrypt the first 16 bytes of cyphertext
	c.Decrypt(result[:16], ctext[:16])
	// decrypt the next 16 bytes of cyphertext. (why separate...?)
	c.Decrypt(result[16:], ctext[16:])

	// xor the plaintext with the xormix slice.
	for i, _ := range xormix {
		result[i] ^= xormix[i]
	}
	return
}

// for the EC mult case.
// same kindof idea but you have 24 byte ciphertext and results.
// but actually there's 32 bytes in 2 16-byte block operations, and
// you need the intermediate 8-bytes which you use then drop.  Sure.
// ctext 24 bytes, xormix and key 32
func superWeirdAESDec(ctext [24]byte, xormix, key [32]byte) (result [24]byte) {
	c, _ := aes.NewCipher(key[:])
	// second block first here, kindof CFB.
	var firstBlock, secondBlock [16]byte
	// decrypt the 16 bytes of end of the cyphertext first. (8 to 24)
	c.Decrypt(secondBlock[:], ctext[8:])
	// xor the decrypted secondBlock with the second half of xormix
	for i, _ := range secondBlock {
		secondBlock[i] ^= xormix[16+i]
	}
	// this gives us secondBlock[:8] = firstBlock[8:16]
	// and secondBlock[8:] = result[16:24]

	// copy the xor'd 8 bytes into the ctext
	copy(ctext[8:16], secondBlock[:8])
	c.Decrypt(firstBlock[:], ctext[:16])

	// xor the firstBlock plaintext with the first half of xormix.
	for i, _ := range firstBlock {
		firstBlock[i] ^= xormix[i]
	}

	// of which 16 come from the firstBlock
	copy(result[:16], firstBlock[:])
	// and 8 come from the latter half of the secondBlock
	copy(result[16:], secondBlock[8:])
	return
}
