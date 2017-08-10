package main

import (
	"bytes"
	"fmt"

	"github.com/adiabat/btcd/wire"
	"github.com/adiabat/goodelivery/extract"
	"github.com/mit-dci/lit/portxo"
)

func (g *GDsession) extractmany() error {
	if *g.inFileName == "" {
		return fmt.Errorf("extract needs input file (-in)")
	}

	filetext, err := g.inputText()
	if err != nil {
		return err
	}

	ptxos, err := extract.ParseBitcoindListUnspent(filetext)
	if err != nil {
		return err
	}

	var outstring string

	// go through each portxo, convert to bytes, then hex, then make a line
	for _, p := range ptxos {
		b, err := p.Bytes()
		if err != nil {
			return err
		}
		outstring += fmt.Sprintf("%x\n", b)
	}

	return g.output(outstring)
}

// extract takes in a hex-encoded transaction, and returns a portxo.
// or if it's a listunspent, then make a bunch of portxos
func (g *GDsession) extractfromtx() error {
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
