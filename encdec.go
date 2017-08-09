package main

import (
	"fmt"

	"github.com/adiabat/btcutil"
	"github.com/adiabat/btcutil/base58"
	"github.com/adiabat/goodelivery/bip38"
)

// dec38 decrypts a BIP38 key into WIF
func (g *GDsession) dec38() error {
	var pass []byte
	var err error

	if *g.bip38key == "" {
		if g.inFile == "" {
			return fmt.Errorf("enc needs input bip38 (-b38, -in)")
		}
		*g.bip38key, err = g.inputText()
		if err != nil {
			return err
		}
	}

	err = bip38.Validate(*g.bip38key)
	if err != nil {
		return fmt.Errorf("BIP38 key decode error: %s", err.Error())
	}
	// drop version byte
	decoded, _, err := base58.CheckDecode(*g.bip38key)
	if err != nil {
		return fmt.Errorf("BIP38 key decode error: %s", err.Error())
	}

	if *g.verbose { // print base58 bytes
		fmt.Printf("decoded base58 to: %x\n", decoded)
	}

	if *g.pass != "" { // check for cli art passphrase
		pass = []byte(*g.pass)
		if *g.verbose {
			fmt.Printf("Using passphrase %s\n", pass)
		}
	} else { // no cli arg, prompt for passphrase
		pass, err = g.prompt("Decrypting BIP38 private key. passphrase: ")
		if err != nil {
			return fmt.Errorf("Passphrase error: %s", err.Error())
		}
	}

	// decrypt to k
	k, compr, err := bip38.Decrypt38(decoded, pass, g.NetParams)

	if err != nil {
		return fmt.Errorf("BIP38 key decrypt error: %s", err.Error())
	}
	if *g.verbose {
		fmt.Printf("Decryption OK\n")
	}
	// turn into WIF format.
	wif, err := btcutil.NewWIF(k, g.NetParams, compr)
	if err != nil {
		return fmt.Errorf("WIF encode error: %s", err.Error())
	}

	var outString string
	if *g.verbose {
		adr, err := btcutil.NewAddressPubKeyHash(
			btcutil.Hash160(wif.SerializePubKey()), g.NetParams)
		if err != nil {
			return err
		}
		outString += fmt.Sprintf("Address: %s\n", adr.String())
		outString += "WIF private key (unencrypted): "
	}
	outString += wif.String()
	return g.output(outString)
}

// enc38 encrypts a WIF key into BIP38
func (g *GDsession) enc38() error {

	var pass []byte
	var err error

	if *g.wifkey == "" {
		if g.inFile == "" {
			return fmt.Errorf("enc needs input wif (-wif, -in)")
		}
		*g.wifkey, err = g.inputText()
		if err != nil {
			return err
		}
	}

	wif, err := btcutil.DecodeWIF(*g.wifkey)
	if err != nil {
		return fmt.Errorf("WIF decode error: %s", err.Error())
	}
	if !wif.IsForNet(g.NetParams) {
		return fmt.Errorf("WIF string / network mismatch")
	}

	if *g.pass != "" {
		pass = []byte(*g.pass)
		if *g.verbose {
			fmt.Printf("Using passphrase %s\n", pass)
		}
	} else {
		pass, err = g.prompt("Encrypting WIF private key. passphrase: ")
		if err != nil {
			return fmt.Errorf("Passphrase error: %s", err.Error())
		}
	}
	es, err := bip38.Encrypt38(wif.PrivKey, wif.CompressPubKey, pass, g.NetParams)
	if err != nil {
		return fmt.Errorf("BIP38 encrypt error: %s", err.Error())
	}

	var outString string
	if *g.verbose {
		adr, err := btcutil.NewAddressPubKeyHash(
			btcutil.Hash160(wif.SerializePubKey()), g.NetParams)
		if err != nil {
			return err
		}
		outString += fmt.Sprintf("Address: %s\n", adr.String())
		outString += "BIP38 private key (encrypted): "
	}
	outString += es
	return g.output(outString)
}
