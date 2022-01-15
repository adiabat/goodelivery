package main

import (
	"bytes"
	"fmt"

	"github.com/adiabat/bech32"
	"github.com/mit-dci/lit/btcutil"
	"github.com/mit-dci/lit/btcutil/base58"
	"github.com/mit-dci/lit/btcutil/txscript"
	"github.com/mit-dci/lit/coinparam"
	"github.com/mit-dci/lit/crypto/koblitz"
	"github.com/mit-dci/lit/lnutil"
	"github.com/mit-dci/lit/portxo"
	"github.com/mit-dci/lit/wire"
)

func (g *GDsession) move() error {
	if *g.inFileName == "" {
		return fmt.Errorf("move requires input file portxo to move (-in)")
	}
	if *g.destAdr == "" {
		return fmt.Errorf("move requires a destination address (-dest)")
	}

	portxBytes := g.inputHex()
	if len(portxBytes) == 0 {
		return fmt.Errorf("no hex in input file")
	}

	txo, err := portxo.PorTxoFromBytes(portxBytes[0])
	if err != nil {
		return err
	}

	// ignore what network it's for
	outScript, err := AdrStringToOutscript(*g.destAdr)
	if err != nil {
		return err
	}

	tx, err := SendOne(*txo, outScript, *g.fee, g.NetParams)
	if err != nil {
		return err
	}

	var buf bytes.Buffer

	err = tx.Serialize(&buf)
	if err != nil {
		return err
	}

	outString := fmt.Sprintf("%x", string(buf.Bytes()))
	return g.output(outString)
}

// AdrStringToOutscript converts an address string into an output script byte slice
// note that this ignores the prefix! Be careful not to mix networks.
// currently only works for testnet legacy addresses
func AdrStringToOutscript(adr string) ([]byte, error) {
	var err error
	var outScript []byte

	// use HRP to determine network / wallet to use
	outScript, err = bech32.SegWitAddressDecode(adr)
	if err != nil { // valid bech32 string
		// try for base58 address
		// btcutil addresses don't really work as they won't tell you the
		// network; you have to tell THEM the network, which defeats the point
		// of having an address.  default to testnet only here

		// could work on adding more old-style addresses; for now use new bech32
		// addresses for multi-wallet / segwit sends.

		// ignore netID here
		decoded, _, err := base58.CheckDecode(adr)
		if err != nil {
			return nil, err
		}

		outScript, err = lnutil.PayToPubKeyHashScript(decoded)
		if err != nil {
			return nil, err
		}
	}
	return outScript, nil
}

// SendOne moves one utxo to a new address, returning the transaction
func SendOne(u portxo.PorTxo, outScript []byte,
	feeRate int64, param *coinparam.Params) (*wire.MsgTx, error) {

	// estimate tx size at 200 bytes
	fee := 200 * feeRate

	sendAmt := u.Value - fee
	tx := wire.NewMsgTx() // make new tx
	// add single output
	// make user specified txout and add to tx
	txout := wire.NewTxOut(sendAmt, outScript)
	tx.AddTxOut(txout)
	tx.AddTxIn(wire.NewTxIn(&u.Op, nil, nil))
	//	tx.AddTxIn(wire.NewTxIn(&u.Op, nil))

	var sigScript []byte
	var empty [32]byte
	//	var wit [][]byte

	if u.PrivKey == empty {
		return nil, fmt.Errorf("error: porTxo has empty private key field")
	}

	priv, _ := koblitz.PrivKeyFromBytes(koblitz.S256(), u.PrivKey[:])

	if priv == nil {
		return nil, fmt.Errorf("SendCoins: privkey error")
	}

	compressed := u.Mode&portxo.FlagTxoCompressed != 0

	// sign into stash
	prevAdr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(priv.PubKey().SerializeCompressed()), param)
	if err != nil {
		return nil, err
	}

	if !compressed {
		prevAdr, err = btcutil.NewAddressPubKeyHash(
			btcutil.Hash160(priv.PubKey().SerializeUncompressed()), param)
		if err != nil {
			return nil, err
		}
	}

	fmt.Printf("got adr %s from wif\n", prevAdr.String())

	prevScript, err := txscript.PayToAddrScript(prevAdr)
	if err != nil {
		return nil, err
	}

	// check if BCH / BTG sigs needed
	if param.Name == "bch" || param.Name == "btg" {

		// make hash cache for this tx
		hCache := txscript.NewTxSigHashes(tx)

		// sighash type is sighashAll, but also has the "forkID" bit set
		hashType := txscript.SigHashAll | txscript.SigHashForkID

		// also put more than the forkID; top 3 bytes can hold different
		// forkID bits which make the sighash different for different
		// altcoins
		// Both sides are just uint32s but gotta cast
		hashType |= txscript.SigHashType(param.ForkID << 8)

		// generate sig.
		sigScript, err = txscript.BCHSignatureScript(
			tx, hCache, 0, u.Value, u.PkScript, hashType, priv, false)
		if err != nil {
			return nil, err
		}
	} else {

		sigScript, err = txscript.SignatureScript(
			tx, 0, prevScript, txscript.SigHashAll, priv, compressed)
		if err != nil {
			return nil, err
		}
	}

	// swap sigs into sigScripts in txins
	if sigScript != nil {
		tx.TxIn[0].SignatureScript = sigScript
	}
	//	if wit != nil {
	//		tx.TxIn[0].Witness = wit
	//		tx.TxIn[0].SignatureScript = nil
	//	}
	return tx, nil
}
