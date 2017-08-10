package main

import (
	"fmt"

	"github.com/adiabat/btcutil"
	"github.com/adiabat/goodelivery/extract"
	"github.com/mit-dci/lit/portxo"
)

// insert puts a private key into a portxo
func (g *GDsession) insert() error {
	if *g.inFileName == "" {
		return fmt.Errorf("insert needs input file (-in)")
	}
	if *g.wifkey == "" {
		return fmt.Errorf("insert needs wif key (-wif, -wiffile)")
	}

	fileslice, err := g.inputHex()
	if err != nil {
		return err
	}

	u, err := portxo.PorTxoFromBytes(fileslice)
	if err != nil {
		fmt.Errorf("file wasn't a tx, and wasn't a utxo! %s\n", err.Error())
	}

	// try to add WIF
	wif, err := btcutil.DecodeWIF(*g.wifkey)
	if err != nil {
		return err
	}
	err = u.AddWIF(*wif)
	if err != nil {
		return err
	}
	if *g.verbose {
		fmt.Printf("%s\n", u.String())
	}
	b, _ := u.Bytes()
	outString := fmt.Sprintf("%x", b)

	return g.output(outString)
}

// insert puts private keys into lots of portxos
func (g *GDsession) insertmany() error {
	if *g.wifkey == "" {
		return fmt.Errorf("insertmany needs wif file (-wiffile)")
	}

	//	filestring, err := g.inputText()
	//	if err != nil {
	//		return err
	//	}

	// get wifs from input file
	wifs, err := extract.ParseBitcoindWIFDump(*g.wifkey)
	if err != nil {
		return err
	}

	var outString string
	for _, w := range wifs {
		outString += fmt.Sprintf("pub %x\n", w.SerializePubKey())
	}

	return g.output(outString)
}
