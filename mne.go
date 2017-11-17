package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/adiabat/btcutil"
	"github.com/adiabat/btcutil/hdkeychain"
	"github.com/mit-dci/lit/coinparam"
	"github.com/mit-dci/lit/portxo"
	"github.com/tyler-smith/go-bip39"
)

/*
mne is a bip39 mnemonic generator / parser

*/

func (g *GDsession) decode39(showwif bool) error {
	var seed []byte
	var err error
	var rawPhrase string

	if *g.inFileName == "" { // read from input if no file
		// setup reader with max 4K input chars
		reader := bufio.NewReaderSize(os.Stdin, 4000)

		fmt.Printf("type all the words here:\n")
		rawPhrase, err = reader.ReadString('\n') // input finishes on enter key
		if err != nil {
			return err
		}
	} else { // read from file instead of keyboard
		mneFile, err := ioutil.ReadFile(*g.inFileName)
		if err != nil {
			return err
		}
		rawPhrase = string(mneFile)
	}
	phraseSlice := strings.Fields(rawPhrase) // chop input up on whitespace
	if len(phraseSlice) < 1 {
		return fmt.Errorf("empty phrase")
	}
	var cleanPhrase string
	for _, word := range phraseSlice {
		cleanPhrase += word
		cleanPhrase += " "
	}
	// strip last space
	cleanPhrase = cleanPhrase[:len(cleanPhrase)-1]
	// check if the user has entered a valid phrase before prompting for salt
	_, err = bip39.MnemonicToByteArray(cleanPhrase)
	if err != nil {
		return err
	}

	if *g.verbose {
		fmt.Printf("%d character mnemonic OK:\n%s\n", len(cleanPhrase), cleanPhrase)
	}

	salt, err := g.prompt("enter salt (just press enter if none): ")
	if err != nil {
		return err
	}

	seed, err = bip39.NewSeedWithErrorChecking(cleanPhrase, string(salt))
	if err != nil {
		return err
	}

	// ugly; need to convert everything over to coinparams
	cparam := new(coinparam.Params)
	cparam.PrivateKeyID = g.NetParams.PrivateKeyID

	masterKey, err := hdkeychain.NewMaster(seed[:], cparam)
	if err != nil {
		return err
	}

	if *g.verbose {
		fmt.Printf("master key address: %s\n", masterKey.String())
	}

	outString, err := g.PrintHDKeys(masterKey, showwif)
	if err != nil {
		return err
	}
	return g.output(outString)
}

func (g *GDsession) new39() error {
	if *g.bits < 128 || *g.bits > 256 || *g.bits%32 != 0 {
		return fmt.Errorf("bitlength must be 128, 160, 192, 224, or 256")
	}

	// add keyboard mashing for tinfoilers who don't trust /dev/urandom?
	noise := make([]byte, *g.bits/8)
	_, err := rand.Read(noise)
	if err != nil {
		log.Fatal(err)
	}

	phrase, err := bip39.NewMnemonic(noise)
	if err != nil {
		log.Fatal(err)
	}

	outString := ""
	if *g.verbose {
		outString += fmt.Sprintf("%d character mnemonic\n", len(phrase))
	}
	outString += fmt.Sprintf("%s", phrase)

	return g.output(outString)
}

//TODO add derivation paths for different wallets.
// Currently uses Core: m/0'/0'/k'
// Hive / Breadwallet: m/0'/0/k ?
// Mycelium / BIP44 standard: m/44'/0'/0'/0/k

func (g *GDsession) PrintHDKeys(
	root *hdkeychain.ExtendedKey, showWIF bool) (string, error) {

	howmany := uint32(*g.index)

	var outString string
	var k portxo.KeyGen

	hard := uint32(1 << 31) // derivation hardening bit
	leafhard := hard        // whether to harden last step

	if *g.bip44 { // bip44 derivation
		k.Depth = 5
		k.Step[0] = 44 | hard

		if g.NetParams.Name == "testnet3" {
			k.Step[1] = 1 | hard
		} else {
			k.Step[1] = 0 | hard
		}

		k.Step[2] = 0 | hard

		k.Step[3] = 0
		if *g.changePath {
			k.Step[3] = 1
		}

		// bip44 defaults to unhardened last step
		leafhard = 0
		if *g.verbose {
			outString += fmt.Sprintf(
				"Using BIP44 standard derivation path m/44'/0'/0'/0/k'\n")
		}

	} else { // core m/0'/0'/k' derivation
		k.Depth = 3
		k.Step[0] = 0 | hard
		k.Step[1] = 0 | hard

		if *g.verbose {
			outString += fmt.Sprintf(
				"Using bicoin core derivation path m/0'/0'/k'\n")
		}
	}

	if false { // breadwallet / hive derivation
		k.Depth = 3
		k.Depth = 3
		k.Step[0] = 0 | hard
		k.Step[1] = 0 | hard
		leafhard = 0
	}

	for i := uint32(0); i < howmany; i++ {

		k.Step[k.Depth-1] = i | leafhard

		priv, err := k.DerivePrivateKey(root)
		if err != nil {
			return "", err
		}

		if *g.verbose {

			outString += fmt.Sprintf("%s - ", k.String())
		}

		if !showWIF || *g.verbose {

			pkHash := btcutil.Hash160(priv.PubKey().SerializeCompressed())
			adr, err := btcutil.NewAddressPubKeyHash(pkHash, g.NetParams)
			if err != nil {
				return "", err
			}
			outString += fmt.Sprintf("%s", adr.String())
		}

		if showWIF {
			wif, err := btcutil.NewWIF(priv, g.NetParams, true)
			if err != nil {
				return "", err
			}
			if *g.verbose {
				outString += " WIF: "
			}
			outString += fmt.Sprintf("%s", wif.String())
		}
		outString += fmt.Sprintf("\n")
	}

	return outString, nil
}
