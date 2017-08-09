package main

import (
	"bytes"
	"fmt"

	"github.com/adiabat/btcd/wire"
	"github.com/adiabat/btcutil"
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

// extract takes in a hex-encoded transaction, and returns a portxo
func (g *GDsession) extract() error {
	if *g.inFileName == "" {
		return fmt.Errorf("extract needs input file (-in)")
	}

	tx := wire.NewMsgTx()
	u := new(portxo.PorTxo)

	fileslice, err := g.inputHex()
	if err != nil {
		return err
	}

	// make buffer
	txbuf := bytes.NewBuffer(fileslice)

	err = tx.Deserialize(txbuf)
	if err != nil {
		return err
	}

	// tx did work, get index and try extracting utxo

	// make sure it has, like, inputs and outputs
	if len(tx.TxIn) < 1 || len(tx.TxOut) < 1 {
		fmt.Errorf("tx has no inputs (or outputs)")
	}

	idx := uint32(*g.index)

	u, err = portxo.ExtractFromTx(tx, idx)
	if err != nil {
		return err
	}

	// assume PKH for now... detect based on pkScript later
	u.Mode = portxo.TxoP2PKHComp

	if *g.verbose {
		fmt.Printf("%s\n", u.String())
	}

	b, err := u.Bytes()
	if err != nil {
		return err
	}

	outString := fmt.Sprintf("%x", b)
	return g.output(outString)
}
