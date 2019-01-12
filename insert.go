package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/adiabat/goodelivery/extract"
	"github.com/mit-dci/lit/btcutil"
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

	fileslice := g.inputHex()
	if len(fileslice) == 0 {
		return fmt.Errorf("no valid hex in input file")
	}

	u, err := portxo.PorTxoFromBytes(fileslice[0])
	if err != nil {
		return fmt.Errorf("file wasn't a tx, and wasn't a utxo! %s\n", err.Error())
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

	filestring, err := g.inputText()
	if err != nil {
		return err
	}

	// get wifs from input file
	wifs, err := extract.ParseBitcoindWIFDump(*g.wifkey)
	if err != nil {
		return err
	}

	var ptxos []*portxo.PorTxo

	// got all the wifs; now get all the un-keyed utxos
	lines := strings.Split(filestring, "\n")
	for _, l := range lines {
		// ascii hex to bytes
		b, err := hex.DecodeString(l)
		if err != nil {
			return err
		}

		u, err := portxo.PorTxoFromBytes(b)
		if err != nil {
			return fmt.Errorf("bad portxo %s\n", err.Error())
		}
		ptxos = append(ptxos, u)
	}

	// now have all the wifs and all the portxos.  Need to match them

	// The naive way is O(n^2)-ish which is bad but fast enough for the small
	// numbers here.  If you need to do this with millions of utxos & keys, well,
	// write something more efficient.
	var hits int
	for i, txo := range ptxos {
		// need i to modify the portxo in place.  Probably
		for _, wif := range wifs {

			// match detection: is this wif the right private key for this utxo?
			var match bool
			if txo.Mode == portxo.TxoP2PKComp && wif.CompressPubKey {
				// TODO match raw pubkey
			}
			if txo.Mode == portxo.TxoP2PKHUncomp && !wif.CompressPubKey {
				// TODO match uncompressed PKH
			}
			if txo.Mode == portxo.TxoP2PKHComp && wif.CompressPubKey {
				pkh := btcutil.Hash160(wif.SerializePubKey())
				if bytes.Equal(txo.PkScript[3:23], pkh) {
					match = true
				}
			}

			if match {
				err = ptxos[i].AddWIF(*wif)
				if err != nil {
					return err
				}
				if *g.verbose {
					fmt.Printf("inserted to utxo %d %s\n", i, ptxos[i].String())
				}
				hits++
				// stop looking for a wif to insert
				break
			}
		}
	}

	fmt.Printf("added keys to %d of %d utxos\n", hits, len(ptxos))

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
