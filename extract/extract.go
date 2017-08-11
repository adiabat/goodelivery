package extract

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/adiabat/btcd/chaincfg/chainhash"
	"github.com/adiabat/btcutil"
	"github.com/mit-dci/lit/portxo"
)

// ParseBitcoindListUnspent parses the text from bitcoin-cli listunspend
// and returns a slice of portxos
func ParseBitcoindListUnspent(s string) ([]portxo.PorTxo, error) {
	fmt.Printf("input string is %d chars\n", len(s))

	utxos := new([]UnspentBitcoind)

	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()

	err := d.Decode(utxos)
	if err != nil {
		return nil, err
	}

	if len(*utxos) == 0 {
		return nil, fmt.Errorf("no utxos \n")
	}

	fmt.Printf("Got %d utxos\n", len(*utxos))

	var ptxs []portxo.PorTxo

	for _, u := range *utxos {
		p, err := ExtractFromJson(u)
		if err != nil {
			return nil, err
		}
		ptxs = append(ptxs, *p)
	}
	return ptxs, nil
}

// ExtractFromJson makes a single portxo from a json struct from
// listunspent
func ExtractFromJson(u UnspentBitcoind) (*portxo.PorTxo, error) {
	p := new(portxo.PorTxo)
	txid, err := chainhash.NewHashFromStr(u.Txid)
	if err != nil {
		return nil, err
	}
	p.Op.Hash = *txid
	p.Op.Index = u.Vout

	p.Value, err = String2Sat(string(u.Amount))

	// check if mode can be determined from the pkscript
	pks, err := hex.DecodeString(u.ScriptPubKey)
	if err != nil {
		return nil, err
	}

	p.Mode = portxo.TxoModeFromPkScript(pks)

	p.PkScript = pks
	if err != nil {
		return nil, err
	}

	//p.AddWIF()
	return p, nil
}

// ParseBitcoindWIFDump takes the file bitcoin-cli dumpwallet makes,
// and returns a slice of WIFs
func ParseBitcoindWIFDump(s string) ([]*btcutil.WIF, error) {
	fmt.Printf("input string is %d chars\n", len(s))

	lines := strings.Split(s, "\n")
	var wifstrings []string
	for _, line := range lines {
		words := strings.Split(line, " ")

		if len(words[0]) > 30 { // && words[0][0] == 'c'
			wifstrings = append(wifstrings, words[0])
		}
	}

	var wifs []*btcutil.WIF

	for _, x := range wifstrings {
		wif, err := btcutil.DecodeWIF(x)
		if err != nil {
			fmt.Printf("can't decode %s as a wif\n")
			// return nil, err
		} else {
			wifs = append(wifs, wif)
		}
	}

	return wifs, nil
}

// UnspentBitcoind is the JSON struct for what bitcoind gives you from a
// listunspent call.
// Remember to capitalize everything or it'll be silently dropped
type UnspentBitcoind struct {
	Txid          string
	Vout          uint32
	Address       string
	ScriptPubKey  string
	Amount        json.Number
	Confirmations int32
	Spendable     bool
	Solvable      bool
}

// String2Sat converts a string that looks like a floating point number of
// bitcoins into a regular int64 of satoshis.
// Note that using float64s and casting doesn't work!!! 0.00025696 -> 25695 !!!

func String2Sat(s string) (int64, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("can't split %d around decimal")
	}
	big, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, err
	}
	small, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, err
	}
	return int64((big * 100000000) + small), nil

}
