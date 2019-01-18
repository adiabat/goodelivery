# goodelivery

(No affiliation with the LBMA)

Command line offline tools for moving coins.

Still under development; not recommended for use with real money.

## usage

goodelivery can be used to split off persistent forks of bitcoin, such as bitcoinCash / BCH.

It can also be used to make simple bitcoin transactions offline, and export the signed transactions to an online computer to be broadcast.

usage is ./goodelivery command -options

## commands 

### new

Make a new BIP39 seed phrase.

options: 

example: 
```
$ ./goodelivery new -v -b 160
93 character mnemonic
equal file express range stumble test useless dish under lend diesel crack elbow practice own
```

### adr

Make some addresses from a BIP39 phrase

example:
```
$ ./goodelivery adr -n 2
type all the words here:
equal file express range stumble test useless dish under lend diesel crack elbow practice own
enter salt (just press enter if none): 
msCvb9ghbhKdLdoAwyyxHtuqJ6PzfLn4XF
mmWaBnAYnWuzii3wkZDfrZxuaveQe1dd5T
```

### key

Make private keys (WIF format) from a BIP39 phrase

example:
```
$ ./goodelivery key -n 3
type all the words here:
equal file express range stumble test useless dish under lend diesel crack elbow practice own
enter salt (just press enter if none): 
cNrMD7E77k3LtaFd3QSshwGPp5Bj3n9mG9iHFy65XQv1gL9K2qRR
cPFB98wiM1USWujT47dqbivH6iaYX2sSUYHn5seDQJuZQcnpNWsZ
cSRe3KiEJS9hrbr8WgDgMkPFm3uRvkkAM5p5zRfPf3AQLWx4X734
```

### extract

Make a portable utxo file from a hex-encoded transactions

### extractmany

Make several portable utxos from the output of bitcoin-cli listunspent

### insert

Add a WIF-encoded private key to a portable utxo

### insertmany

Add many WIF-encoded private keys to the output from extractmany.

goodelivery will figure out which private key to put where.  It's not optimized but should be fast enough for lists of less than a few hundred outputs.

The file with WIF keys comes from bitcoin-cli dumpwallet.  Other files with WIF keys should also work.  Specify this WIF file with -wiffile.

Specify the file with portable utxos with -in.  The utxos with included private keys will be printed to the terminal or saved to the file specified by -out.

### move

Create a 1-input, 1-output transaction which spends the utxo specified by -in, and sends it to the address specified by -dest.  The signed transaction is output in hex format to the terminal, or saved to a file specified by the -out 

## options

`-in <filename>` input file name

`-out <filename>` output file name

`-wiffile <filename>` input file with WIF private keys

`-wifkey <wif>`  use the WIF key from the command line

`-dest <base58>` send to this base58 encoded address

`-pass <string>` use this password / salt from the command line

`-b <int>` specify the bitlength of the mnemonic seed to use.  The default is 128 bit, which results in a phrase of 12 words.  More bits gives more words.  Options are 128, 160, 192, 224, or 256. 

`-index <int>` when extracting a utxo from a raw transaction, pull out this index

`-fee <int>` when sending, use this fee rate (in satoshis per byte)

`-echo` when typing in a password, show it on the terminal

`-star` when typing in a password, show **** on the terminal

`-v` be verbose and print a bunch of stuff on the terminal.  Does not affect -out

`-main` use mainnet instead of testnet3

`-bch` use BCH network and signature algo

`-b44` use the bip44 path for key derivation, instead of the bitcoin core's keypath

