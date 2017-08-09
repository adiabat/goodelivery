package extract

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mit-dci/lit/portxo"
)

func ParseBitcoindListUnspent(s string) error {
	fmt.Printf("input string is %d chars\n", len(s))

	utxos := new([]UnspentBitcoind)

	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()

	err := d.Decode(utxos)
	if err != nil {
		return err
	}

	if len(*utxos) == 0 {
		return fmt.Errorf("no utxos \n")
	}

	fmt.Printf("Got %d utxos\n", len(*utxos))

	var sum int64
	//	var fsum float64
	for _, u := range *utxos {
		p := new(portxo.PorTxo)

		if u.Spendable {
			amt, err := String2Sat(string(u.Amount))
			if err != nil {
				return err
			}
			sum += amt
			//			fsum += u.Amount
		}
		if !u.Spendable {
			fmt.Printf("unspendable ")
		}

	}
	fmt.Printf("total coin is %d\n", sum)
	return nil
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
