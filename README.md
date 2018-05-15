<p>
<img src="https://www.chainside.net/images/logo.png" alt="chainside" width="80"> 
<br \><br \>
developed with :heart: by <a href="https://www.chainside.net">chainside</a>
</p>


# btcpy
`btcpy` is a Python3 SegWit-compliant library which provides tools to handle
Bitcoin data structures in a simple fashion. In particular, the main goal of
this library is to provide a simple interface to parse and create complex
Bitcoin scripts.

**N.B.: this library is a work in progress so it is highly discouraged to use it in
a production environment. Also, as long as the version is 0.\*, API breaking changes
should be expected**


Table of Contents
=================

   * [btcpy](#btcpy)
   * [Table of Contents](#table-of-contents)
   * [Requirements](#requirements)
   * [Installation](#installation)
   * [What it does](#what-it-does)
   * [What it does not do](#what-it-does-not-do)
   * [Structure](#structure)
   * [Usage examples](#usage-examples)
      * [Setup](#setup)
         * [Network](#network)
         * [Strictness](#strictness)
      * [Parsing and serialization](#parsing-and-serialization)
      * [Keys](#keys)
         * [HD keys](#hd-keys)
      * [Scripts](#scripts)
         * [Low-level scripting functionalities](#low-level-scripting-functionalities)
      * [Addresses](#addresses)
      * [Transactions](#transactions)
         * [Creating transactions](#creating-transactions)
         * [Spending a transaction](#spending-a-transaction)
         * [P2PKH](#p2pkh)
         * [P2SH](#p2sh)
         * [P2WSH](#p2wsh)
         * [P2WSH-over-P2SH](#p2wsh-over-p2sh)
         * [P2PK](#p2pk)
         * [Multisig](#multisig)
         * [Timelocks, Hashlocks, IfElse](#timelocks-hashlocks-ifelse)
         * [Low-level signing](#low-level-signing)
   * [Contributing and running tests](#contributing-and-running-tests)
   * [Roadmap to v1](#roadmap-to-v1)
   * [TODO](#todo)
   * [Acknowledgements](#acknowledgements)


# Requirements
The strict requirements of this library are:

    pip install ecdsa
    pip install base58
    
as an additional requirement, only used for integration testing purposes, this
library uses:

    pip install python-bitcoinlib==0.7.0
    
this is used to communicate with the Bitcoin node in order to test transactions
validation.

# Installation
To install this library and its dependencies one can just run

    pip install chainside-btcpy

# What it does
The main functionalities provided by this project are the following.

* Parsing of blocks
* Parsing, creation and signing of transactions
* Parsing and creation of scripts. This also includes many nonstandard script
types such as:
    * Hashlocked scripts
    * Timelocked scripts, with both absolute and relative times
    * Arbitrarily nested if-else clauses

  all scripts are easily embeddable in P2SH and P2WSH format, also
  supporting SegWit-over-P2SH formats. This library also offers functions to
  spend such complex scripts by only providing the necessary data.

# What it does not do
This library does not implement the following functionalities:

* Validation: when blocks, transactions and scripts are parsed, only
format errors are reported. No proof-of-work validation, script execution, 
transaction validation and signature verification is performed. For these
consensus-critical functionalities, users of this library should rely on
Bitcoin Core or other libraries that perform validation.
* Communication with the Bitcoin nodes. This is not provided neither on an RPC
nor a networking level. For this purpose we highly recommed python-bitcoinlib.

# Structure
All important data structures can be found in `btcpy.structs`, helper modules
are located in `btcpy.lib`. Objects in `btcpy.structs` are meant as a public
interface, while objects located in `btcpy.lib` are used internally.

# Usage examples

## Setup
The first thing to do the first time this package is imported is to set a global state which
indicates on which network you are working and wether you want strict mode enabled.
These two settings are further explained in the following sections.

To setup `btcpy`, you can use the following function

```python
from btcpy.setup import setup
setup('regtest', strict=True)
```

### Network
You can setup the network you will work on by calling:

```python
from btcpy.setup import setup
setup('regtest')
```
    
supported network types are:
    
    regtest
    testnet
    mainnet

The `btcpy.setup` module also provides the following network-related functions:

    is_mainnet() - returns True if 'mainnet' was selected, False otherwise
    net_name()   - returns the value that was selected when calling setup()

### Strictness
`btcpy` never performs validation. However, we don't want you to inadvertently lose your funds
for a mistake, so, in strict mode, when you do something that looks dangerous, the library
always makes sure that you know exactly what you are doing.

To setup the library in strict mode, you can run the setup as follows:

```python
setup(my_network, strict=True)  # True is actually the default for strict mode, the only other option is False
```

Additionally, you can force (non-)strictness on specific functions that have a `strict=None`
as keyword argument. If the `strict` keyword argument is left to `None`, then the strictness
specified in the `setup` will be followed, otherwise the param you pass to `strict` will be used.

The following additional checks are done when in `strict` mode:
* Do not allow to create `P2pkScript`s with public keys that have an invalid format (please note that
during parsing such scripts will not even be recognised as scripts of type `'p2pk'`
when strict mode is enabled, they will instead be recognised as of type `'nonstandard'`)
* Do not allow to create m-of-n `MultisigScript`s with less than `m` public keys that have a valid format
(please note that during parsing such scripts will not even be recognised as scripts of type `'multisig'`
when strict mode is enabled, they will instead be recognised as of type `'nonstandard'`)
* Do not allow to decode `ExtendedPublicKeys` or `ExtendedPrivateKeys` that don't match the network you set in `setup`
* Do not allow to decode `Address`es that don't match the network you set in `setup`
    
## Parsing and serialization
`Transaction`, `PublicKey`, `PrivateKey` and `Block` can be extracted
from a hex string by doing:

```python
from btcpy.structs.transaction import Transaction
from btcpy.structs.block import Block
from btcpy.structs.crypto import PublicKey, PrivateKey
tx = Transaction.unhexlify(hex_tx)
block = Block.unhexlify(hex_block)
pubk = PublicKey.unhexlify(pubk_hex)
privk = PrivateKey.unhexlify(privk_hex)
```

`PublicKey` and `PrivateKey` can also be extracted from their BIP32 formats using the
`hd` module:

```python
>>> from btcpy.structs.hd import ExtendedPrivateKey, ExtendedPublicKey
>>> priv = ExtendedPrivateKey.decode('tprv8kxXxKwakWDtXvKBjjR5oHDFS7Z21HCVLMVUqEFCSVChUZ26BMDDH1JmaGUTEYGMUyQQBSfTgEK76QBvLephodJid5GTEiGFVGJdEBYptd7')
# priv.key holds a `PrivateKey`
>>> priv.key.hexlify()
'a12618ff6540dcd79bf68fda2faf0589b672e18b99a1ebcc32a40a67acdab608'
>>> pub = ExtendedPublicKey.decode('tpubDHea6jyptsuZRPLydP5gCgsN194xAcPPuf6G7kHVrm16K3Grok2oTVvdkNvPM465uuKAShgba7A2hHYeGGuS9B8AQGABfc6hp7mpcLLJUsk')
# pub.key holds a `PublicKey`
>>> pub.key.hexlify()
'025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260'
```
`PrivateKey` can also be extracted from a Wallet Import Format by doing:
```python
>>> privk = PrivateKey.form_wif(wif_key)
```

All these structures can be converted back to hex by using their `hexlify()` method.

In the same way, these structures can be serialized and deserialized by using their
`serialize()` and `deserialize()` methods. These methods respectively return and
expect a `bytearray` type.

## Keys
The `PublicKey` class can handle both compressed and uncompressed public
keys. In any case both the compressed and uncompressed version can be extracted.
However, the structure will remember how it was initialised, so the `hexlify()`,
`hash()` and `to_address()` methods will produce different
results depending whether the `PublicKey` was initialised with a compressed or
uncompressed public key. The `to_segwit_address()` method will always consider
the key as compressed (P2WPKH addresses are only allowed with compressed keys).
An example of this behaviour follows:

```python
>>> uncomp = PublicKey.unhexlify('04ea4e183e8c751a4cc72abb7088cea79351dbfb7981ceb48f286ccfdade4d42c877d334c1a8b34072400f71b2a900a305ffae8963075fe94ea439b4b57978e9e8')
>>> compr = PublicKey(uncomp.compressed)
>>> uncomp.hexlify()
'04ea4e183e8c751a4cc72abb7088cea79351dbfb7981ceb48f286ccfdade4d42c877d334c1a8b34072400f71b2a900a305ffae8963075fe94ea439b4b57978e9e8'
>>> compr.hexlify()
'02ea4e183e8c751a4cc72abb7088cea79351dbfb7981ceb48f286ccfdade4d42c8'
>>> str(uncomp.to_address())
'mtDD9VFhPaRi6C6McMSnhb7nUZceSh4MnK'
>>> str(uncomp.to_segwit_address())
'tb1qxs0gs9dzukv863jud3wpldtrjh9edeqqqzahcz'  # this actually refers to the compressed version!
>>> str(compr.to_address())
'mkGY1QBotzNCrpJaEsje3BpYJsktksi3gJ'
>>> str(compr.to_segwit_address())
'tb1qxs0gs9dzukv863jud3wpldtrjh9edeqqqzahcz'
```

Please note that by default the `to_address()` and `to_segwit_address()`
methods will return an address in the format of the network type
specified in `setup` (`regtest` in the case of this example) but a flag
can be passed to it to return an address for another network:

```python
>>> str(uncomp.to_address(mainnet=True))
'1DhFrSAiaYzTK5cjtnUQsfuTca1wXvXfVY'
>>> str(compr.to_address(mainnet=True))
'15kaiM6q5xvx5hpxXJmGDGcDStABoGTzSX'
```

The `PublicKey` derived from a `PrivateKey` can be obtained by doing:

```python
pubk = PrivateKey.unhexlify(privk_hex).pub()
```

the `pub()` method will return by default the compressed public key.
The uncompressed version can be obtained by adding the flag `compressed=False`.

Additionally, one can make sure to use the compressed version of a key by
using its `compress()` method:
```python
>>> compr = uncomp.compress()
>>> str(compr.to_address())
'mkGY1QBotzNCrpJaEsje3BpYJsktksi3gJ'
```

Addresses can be either created from a `PublicKey` or from a script.
In particular this second use case will be documented in the **Addresses** section.

### HD keys
The `structs.hd` module provides functionalities to handle BIP32 HD keys.
Specifically, it provides the following two classes:

* `ExtendedPublicKey`
* `ExtendedPrivateKey`

These classes both provide the `get_child(index, hardened=False)` method. If
called on an `ExtendedPublicKey`, `hardened` must be set to `False`, otherwise
`heardened` can be either `True` or `False`. The `ExtendedPublicKey` corresponding
to an `ExtendedPrivateKey` can be obtained through the `pub()` method.

As seen in the example above, `ExtendedPublicKey` and `ExtendedPrivateKey`
contain the simpler structures `PublicKey` and `PrivateKey`, respectively.
These structures can be accessed through the `key` attribute.

`ExtendedPublicKey`s also provide a `derive()` method which takes as input a string
representing a path which either starts with `'m'` or with `'.'`. `'m'` indicates an
absolute path and can be used only when `derive()` is called on a master key, `'.'`
represents a relative path and can be used from any starting key. Examples of
derivation paths:
* `m/0'/1'/2`: absolute path, first two derivations hardened
* `./0/128/256'`: relative path, last derivation hardened


## Scripts
The main focus of this project is providing a simple way to create complex scripts. Scripts have
the following hierarchy
* `BaseScript`
  * `ScriptSig`
  * `ScriptPubKey`
    * `P2pkhscript`
    * `P2wpkhScript`
      * `P2wpkhV0Script`
    * `P2shScript`
    * `P2wshScript`
      * `P2wshV0Script`
    * `P2pkScript`
    * `NulldataScript`
    * `MultisigScript`
    * `IfElseScript`
    * `TimelockScript`
    * `RelativeTimelockScript`
    * `Hashlock256Script`
    * `Hashlock160Script`
    * `UnknownScript`
    
Scripts have the following methods:
```python
serialize()              - Returns the script as a bytearray
decompile()              - Returns a string representing the human readable opcodes and pushdata operations
hexlify()                - Returns the script as a hex string
unhexlify(hex_string)    - Creates the script from a hex string
is_standard()            - Returns whether the script complies with standardness rules as of Bitcoin Core commit a90e6d2bffc422ddcdb771c53aac0bceb970a2c4
type                     - A property containing a string which represents the type of the script
get_sigop_count()        - Returns the number of signature operations performed by the script
is_push_only()           - Returns whether the script is only made of push operations
to_address(segwit=False) - (only ScriptPubKey) Returns the script as either a P2SH or a P2WSH address, depending whether
                           the segwit flag is set
```

### Low-level scripting functionalities
This section will introduce low-level creation and template-matching of scripts,
for more advanced features please refer to the **Transactions** section.

This libary allows to create scripts from asm and from hex, as can be seen in
the following examples.

Creating a script from asm (i.e. opcodes):
```python
# this returns a bytearray with the compiled script
>>> compiled = Script.compile('OP_DUP OP_HASH160 a33ce8cf2760e2f9ef384bcbbe9a5491759feb14 OP_EQUALVERIFY OP_CHECKSIG')
# the bytearray can be passed to Script() to get a generic script
>>> script = Script(compiled)
# check that everything works as expected
>>> script.decompile()
'OP_DUP OP_HASH160 a33ce8cf2760e2f9ef384bcbbe9a5491759feb14 OP_EQUALVERIFY OP_CHECKSIG'
# beware, this is a generic script, no type recognition has been performed!
>>> script.type
'Script'
```

Creating a script from hex:
```python
# this returns a bytearray with the compiled script
>>> script = Script.unhexlify('76a914a33ce8cf2760e2f9ef384bcbbe9a5491759feb1488ac')
# check that everything works as expected
>>> script.decompile()
'OP_DUP OP_HASH160 a33ce8cf2760e2f9ef384bcbbe9a5491759feb14 OP_EQUALVERIFY OP_CHECKSIG'
# beware, this is a generic script, no type recognition has been performed!
>>> script.type
'Script'
```

As we have seen, these are instantiated as generic scripts, if we want to obtain the appropriate
script type, the `ScriptBuilder` class can be used. `ScriptBuilder`'s method `identify()`
will return the appropriate script type by performing template matching on the provided
script.

Identifying a P2PKH script:
```python
>>> script = ScriptBuilder.identify('76a914341e8815a2e5987d465c6c5c1fb56395cb96e40088ac')
>>> script.type
'p2pkh'
>>> script.decompile()
'OP_DUP OP_HASH160 341e8815a2e5987d465c6c5c1fb56395cb96e400 OP_EQUALVERIFY OP_CHECKSIG'
>>> script.pubkeyhash
bytearray(b'4\x1e\x88\x15\xa2\xe5\x98}F\\l\\\x1f\xb5c\x95\xcb\x96\xe4\x00')
```

Identifying a P2SH script
```python
>>> script = ScriptBuilder.identify('a914bb18ed39c2a86f75f7bb5a9b36ba3581d77fd0f087')
>>> script.type
'p2sh'
>>> script.decompile()
'OP_HASH160 bb18ed39c2a86f75f7bb5a9b36ba3581d77fd0f0 OP_EQUAL'
>>> script.scripthash
bytearray(b'\xbb\x18\xed9\xc2\xa8ou\xf7\xbbZ\x9b6\xba5\x81\xd7\x7f\xd0\xf0')
```

Of course, all the types listed at the beginning of this section can be recognised,
see the next section for more complex script types.

Please keep in mind that the fact that a script is successfully built (a script can be built
for every recognised script type, if no type matches, an `UnknownScript` is istantiated) does
not mean that the script is valid. In fact, `UnknownScript`s can even contain non valid push
operations or non-existing opcodes. The only way to know if a script is valid is executing it
against an execution stack, a functionality that this library does not implement. In particular,
for non-valid push operations, the script asm (obtained through the `decompile` or `__str__` methods)
will contain `[error]` where the push takes place. For non-existing opcodes the asm will contain
the special opcode `OP_INVALIDOPCODE`. These two beahviours match Bitcoin Core's behaviour when
producing script asm.

## Addresses

Supported addresses are: `P2pkhAddress`, `P2shAddress`, `P2wpkhAddress` and `P2wshAddress`.
These constructors can be used to build an address from a hash (plus a SegWit version in the
case of `P2wpkhAddress` or `P2wshAddress`), for example:

```python
from btcpy.structs.crypto import PublicKey
from btcpy.structs.address import P2pkhAddress, P2wpkhAddress
pubk = PublicKey.unhexlify('02ea4e183e8c751a4cc72abb7088cea79351dbfb7981ceb48f286ccfdade4d42c8')
address = P2pkhAddress(pubk.hash())
sw_address = P2wpkhAddress(pubk.hash(), version=0)
print(str(address))  # prints "mkGY1QBotzNCrpJaEsje3BpYJsktksi3gJ"
print(str(sw_address))  # prints "tb1qxs0gs9dzukv863jud3wpldtrjh9edeqqqzahcz"
```

Please note that by default all the address constructors will return an address in the
format of the network type specified in setup (testnet in the case of this example) but
a flag can be passed to them to return an address for another network:

```python
address = P2pkhAddress(pubk.hash(), mainnet=True)
sw_address = P2wpkhAddress(pubk.hash(), version=0, mainnet=True)
print(str(address))  # prints "15kaiM6q5xvx5hpxXJmGDGcDStABoGTzSX"
print(str(sw_address))  # prints "bc1qxs0gs9dzukv863jud3wpldtrjh9edeqq2yxyr3"
```

However, a more common usecase is generating an address for a script, for this the `from_script`
static method of all address classes can be used, in particular:

* `P2pkhAddress.from_script(script, mainnet=None)` will instantiate a `P2pkhAddress` from a
`P2pkhScript`, raising `WrongScriptType` exception in case another type of script is provided.
* `P2shAddress.from_script(script, mainnet=None)` will instantiate a `P2shAddress` representing
the script address if a `P2shscript` is provided, while returning the address of the script
embedded in P2SH format if other script types are provided.
*  `P2wpkhAddress.from_script(script, version, mainnet=None)` will instantiate a `P2wpkhAddress`
 from a `P2wpkhScript`, raising `WrongScriptType` exception in case another type of script
 is provided.
* `P2wshAddress.from_script(script, version, mainnet=None)` will instantiate a `P2wshAddress`
representing the script address if a `P2wshscript` is provided, while returning the address
of the script embedded in P2WSH format if other script types are provided.

The only scripts that directly support an address (i.e. `P2pkhScript`, `P2wpkhScript`,
`P2shscript`, `P2wshScript`) also provide a helper method `address()` to return the script
address, for all other script types will return `None` if the `address()` method is called
and will need to be explicitly converted to P2SH or P2WSH format to obtain an address. Some
examples follow:

```python
>>> str(P2pkhAddress.from_script(P2pkhScript(pubk)))
'mkGY1QBotzNCrpJaEsje3BpYJsktksi3gJ'
>>> str(P2pkhScript(pubk).address())
'mkGY1QBotzNCrpJaEsje3BpYJsktksi3gJ'
>>> str(P2pkhAddress.from_script(P2shScript(P2pkhScript(pubk))))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File ".../btcpy/btcpy/structs/address.py", line 120, in from_script
    raise WrongScriptType('Trying to produce P2pkhAddress from {} script'.format(script.__class__.__name__))
btcpy.structs.address.WrongScriptType: Trying to produce P2pkhAddress from P2shScript script
>>> str(P2shAddress.from_script(P2shScript(P2pkhScript(pubk))))
'2NAJWD6EnXMVt16HUp5vmfwPjz4FemvPhYt'
>>> str(P2shScript(P2pkhScript(pubk)).address())
'2NAJWD6EnXMVt16HUp5vmfwPjz4FemvPhYt'
>>> str(P2wpkhAddress.from_script(P2wpkhV0Script(pubk)))
'tb1qxs0gs9dzukv863jud3wpldtrjh9edeqqqzahcz'
>>> str(P2wpkhV0Script(pubk).address())
'tb1qxs0gs9dzukv863jud3wpldtrjh9edeqqqzahcz'
>>> str(P2wpkhAddress.from_script(P2shScript(P2wpkhV0Script(pubk))))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File ".../btcpy/btcpy/structs/address.py", line 158, in from_script
    raise WrongScriptType('Trying to produce P2pkhAddress from {} script'.format(script.__class__.__name__))
btcpy.structs.address.WrongScriptType: Trying to produce P2pkhAddress from P2shScript script
```

## Transactions

### Creating transactions

Transactions can be created by using the following classes:
* `TxIn`, takes as input the following parameters:
  * `txid`, the txid of the transaction being spent
  * `txout`, the output number of the output being spent
  * `script_sig`, a scriptSig
  * `sequence`, the sequence number of the TxIn
* `Sequence`, the constructor takes a sequence number, but it offers a couple of helper static
methods for creation:
  * `create()`, which takes `seq`, lower 16 bits of sequence number, `blocks`, whether the `seq`
   param expresses blocks or a timestamp, and `disable` which sets the disable bit. For further
   info on how this all works, please refer to
   [BIP68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki) specification.
  * `max()`, this automatically creates a `Sequence` object with the maximum sequence number
   (i.e. `0xffffffff`).
* `ScriptSig`, this can be initialised with a `bytearray` representing the script, but offers
the following static methods:
  * `empty()`, this creates an empty `ScriptSig`, useful when initialising a transaction
  which has not been signed yet
* `StackData`, this class represents data that scripts push on the stack, it offers methods
to convert between the push operations and the actual data pushed.
* `Witness`, this represents a SegWit witness, it is constructed with an array of `StackData`.
* `TxOut`, takes as input the following parameters: `value` the value spent, in satoshis, `n`,
the output number, `script_pubkey`, an object of type `ScriptPubKey` where the coins are being
sent.
* `ScriptPubKey` and derived classes, they take as input a `bytearray` representing the script
but can also be created through the `ScriptBuilder.identify()` method or in the way displayed
later in this section.
* `Locktime`, takes as input a number representing the transaction's locktime field.
* `Transaction`, takes as inputs: a version number, a list of `TxIn`s, a list of `TxOut`s, a
`Locktime`.
* `SegWitTransaction`, has the same interface as `Transaction`

All the aforementioned classes are `Immutable`, this means that, after construction, their
attributes can't be mutated. This helps caching values returned by their methods. The classes
`Transaction`, `SegWitTransaction` and `TxIn` have mutable versions, unsurprisingly called
`MutableTransaction`, `MutableSegWitTransaction` and `MutbleTxIn`, respectively. These mutable
versions are mainly used to create unsigned transactions which then are mutated
to add signatures to them. We will see how to use these in the rest of this section.

Example of a transaction creation:

```python
>>> from btcpy.structs.transaction import Transaction, TxIn, Sequence, TxOut, Locktime
>>> script_sig = Script.unhexlify('48304502210083e6e7507e838a190f0443441c0b62d2df94673887f4482e27e89ff415a90392022050575339c649b85c04bb410a00b62325c1b82c537135fa62fb34fae2c9a30b0b01210384478d41e71dc6c3f9edde0f928a47d1b724c05984ebfb4e7d0422e80abe95ff')
>>> script_pubkey = ScriptBuilder.identify('76a914905f77004d081f20dd421ba5288766d56724c3b288ac')
>>> tx = Transaction(version=1,
...                  ins=[TxIn(txid='1a5a4f9a0d34cfca187db4fe6a3316f46264984c4b4c9fdb582123815afd508f',
...                            txout=0,
...                            script_sig=script_sig,
...                            sequence=Sequence.max())],
...                  outs=[TxOut(value=193000000,
...                              n=0,
...                              script_pubkey=script_pubkey)],
...                  locktime=Locktime(0))
>>> tx.txid
'14e6afbae7d2b1825b7ee711cbcad77d519767b70f5a1e70e5ba7f0bfc902e81'
```

Example creation of a SegWit transaction:

```python
>>> from btcpy.structs.transaction import SegWitTransaction, Witness
>>> from btcpy.structs.script import StackData, empty_script
>>> witness_sig = StackData.from_bytes(unhexlify('304402200d0fbf48270e690be17cb0c47ee6ce2df3b671c2e4b196065e09c6df649b807c022056d8f10da83b2856458152c7f09e53a3495f3fbdd2e20638586a52ddff4f495b01'))
>>> witness_pubkey = StackData.from_bytes(unhexlify('02a079cb0269c933b1ee041a933092c9c439dd1b3a4eebd32ae391cf815002d378'))
>>> witness = Witness([witness_sig, witness_pubkey])
>>> script_pubkey = ScriptBuilder.identify('a914b2eb061810dac0614ac3e06d1bc55077b32b3b2687')
>>> tx = SegWitTransaction(version=1,
...                        ins=[TxIn(txid='1a5a4f9a0d34cfca187db4fe6a3316f46264984c4b4c9fdb582123815afd508f',
...                                  txout=0,
...                                  script_sig=empty_script,
...                                  sequence=Sequence.max(),
...                                  witness=witness],
...                        outs=[TxOut(value=193000000,
...                                    n=0,
...                                    script_pubkey=script_pubkey)],
...                        locktime=Locktime(0))
>>> tx.txid
'14dd31532ca06d62121fd13d35a2c9090246291960e73bf2bb3615abcb1bedab'
```

Of course, nobody would like to create transactions in such a cumbersome way. In fact,
this library provides the appropriate tools to create complex scriptPubKeys in an easy
fashion and to automatically fill in scriptSigs and witnesses of a spending transaction
based on the minimum needed parameters. In the following sections we will show some
examples of these features.

The supported scripts can be created by using their constructor and passing them the
needed parameters. They can be found in `btcpy.structs.script`. All the constructors of these classes can take an input of type `Script`.
In this case they try to match it to their template and raise a `WrongScriptTypeException`
if the script does not match the desired template. Otherwise, they take the following
parameters:

| Class                         | Description |Parameters      |
| ----------------------------- | ----------- | -------------- |
| `P2pkhScript`, `P2wpkhScript` | A P2PKH/P2WPKH script | Either a `PublickKey`, a `bytearray` representing a public key hash or an `Address`           |
| `P2shScript`                  | A P2SH script  | Either a `ScriptPubKey` representing the redeemScript, a `bytearray` representing the redeemScript's hash or an `Address`   |
| `P2wshScript`                 | A P2WSH script | Either a `ScriptPubKey` representing the witnessScript, a `bytearray` representing the witnessScript's hash or an `Address`  |
| `P2pkScript`                  | A P2PK script | A `PublicKey` |
| `NulldataScript`              | An OP_RETURN script | A `StackData` representing the data to store in the transaction |
| `MultisigScript`              | A multisig script, where m out of n keys are needed to spend | `m`, the number of signatures needed to spend this output, an arbitrary number of `PublicKeys`, `n` the number of public keys provided |
| `IfElseScript`              | A script consisting of an `OP_IF`, a script, an `OP_ELSE`, another script and an `OP_ENDIF` | Two `ScriptPubKey` scripts, the first to be executed in the if branch, the second to be executed in the else branch |
| `TimelockScript`              | A script consisting of `<pushdata> OP_CHECKLOCKTIMEVERIFY OP_DROP` and a subsequent script which can be spent only after the absolute time expressed by the `<pushdata>` is expired | A `Locktime`, expressing the absolute time/number of blocks after which the subsequent script can be spent, and the locked `ScriptPubKey` |
| `RelativeTimelockScript`      | A script consisting of `<pushdata> OP_CHECKSEQUENCEVERIFY OP_DROP` and a subsequent script which can be spent only after the relative time time expressed by the `<pushdata>` is expired | A `Sequence`, expressing the relative time/ number of blocks after which the subsequent script can be spent, and the locked `ScriptPubKey` |
| `Hashlock256Script`           | A script consisting of `OP_HASH256 <pushdata> OP_EQUALVERIFY` and a subsequent script which can be spent only after providing the preimage of `<pushdata>` for the double SHA256 hash function | Either a `bytearray` or `StackData` representing the hashed value that locks the subsequent script, plus the locked `ScriptPubKey` |
| `Hashlock160Script`           | A script consisting of `OP_HASH160 <pushdata> OP_EQUALVERIFY` and a subsequent script which can be spent only after providing the preimage of `<pushdata>` for the RIPEMPD160 of the SHA256 hash function | Either a `bytearray` or `StackData` representing the hashed value that locks the subsequent script, plus the locked `ScriptPubKey` |
  
Please note that in the following sections we will frequently use the same keypair for ease of
documenting, of course this is a very bad practice in a production environment
and should be avoided at all costs.

### Spending a transaction
This library offers `Solver`s to spend a previous transaction's output. Solvers can be found in `btcpy.structs.sig` and 
expect as input all the data needed to create the appropriate scriptSig and witness.
To create a `Solver`, the `Sighash` class is needed. This class represents a SIGHASH
and its constructor takes two parameters:
* `sighash`, either of the literal strings `'ONE'`, `'ALL'` or `'NONE'`
* `anyonecanpay`, a flag defaulting to `False`.

The following solvers take one sighash as last parameter, defaulting to `Sighash('ALL')`:
* `P2pkhSolver`
* `P2wpkhV0Solver`
* `P2pkSolver`

The `MultisigSolver` class takes many sighashes as additional last parameters, all
defaulting to `Sighash('ALL')`. All other classes do not accept sighashes.

Additionally, the following solvers are available and they take the following inputs:

| Class            | Inputs                                                                                               | Solves            |
|------------------|----------------------------------------------------------------------------------------------------- |-------------------|
| `P2pkhSolver`    | a `PrivateKey`                                                                                       | `P2pkhScript`     |
| `P2wpkhV0Solver` | a `PrivateKey`                                                                                       | `P2wpkhV0Script`  |
| `P2pkSolver`     | a `PrivateKey`                                                                                       | `P2pkhScript`     |
| `P2shSolver`     | a `ScriptPubKey`, representing the redeemScript and a `Solver` which solves the redeemScript         | `P2shScript`      |
| `P2wshV0Solver`  | a `ScriptPubKey`, representing the witnessScript and a `Solver` which solves the inner witnessScript | `P2wshV0Script`   |
| `MultisigSolver` | an arbitrary number of `PrivateKey`s                                                                 | `MultisigScript`  |
| `IfElseSolver`   | an object of type `Branch`. This is an enum and its values are `Branch.IF` and `Branch.ELSE`, these are used to specify whether we are spending the `if` or `else` branch of the script. The second parameter is a `Solver` for the script inside the desired branch. | `IfElseScript` |
| `TimelockSolver` | a `Solver` of the inner timelocked script | `TimelockedScript`, `RelativeTimelockScript` |
| `HashlockSolver` | the preimage needed to spend the script, as a `bytearray`, and a `Solver` for the hashlocked script | `Hashlock256Script`, `Hashlock160Script` |


To spend a previous transaction, the `MutableTransaction` class provides the `spend()` method.
The `spend()` method expects the following inputs:
* `txouts`, an array of `TxOut`s being spent by the transaction's inputs, in the correct
order.
* `solvers`, an array of `Solver`s, one per input, in the correct order

for example:

```python
>>> from btcpy.structs.sig import *
>>> to_spend = Transaction.unhexlify('...')
>>> unsigned = MutableTransction(version=1,
...                              ins=[TxIn(txid=to_spend.txid,
...                                        txout=0,
...                                        script_sig=ScriptSig.empty(),
...                                        sequence=Sequence.max())],
...                              outs=[TxOut(value=100000,
...                                          n=0,
...                                          script_pubkey=P2pkhScript(pubk))],
...                              locktime=Locktime(0))
>>> solver = P2pkhSolver(privk)
>>> signed = unsigned.spend([to_spend.outs[0]], [solver])
```

In particular, the `spend()` method automatically recognises whether we are spending a SegWit transaction,
hence returning either a `Transaction` or a `SegWitTransaction`.

Now, let's see how more complex scripts can be created and spent. In the following examples, in solvers,
we will always use the default SIGHASH_ALL, to change this, as described above, one can use the
last parameter of the solvers that accept SIGHASHes.

### P2PKH

This is how a P2PKH script can be created:

```python
# create public key
>>> pubk = PublicKey.unhexlify('025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260')
# create P2PKH script
>>> p2pkh_script = P2pkhScript(pubk)
>>> p2pkh_script.hexlify()
'76a914905f77004d081f20dd421ba5288766d56724c3b288ac'
>>> str(p2pkh_script)
'OP_DUP OP_HASH160 905f77004d081f20dd421ba5288766d56724c3b2 OP_EQUALVERIFY OP_CHECKSIG'
```

and this is an example of a P2PKH solver:

```python
>>> privk = PrivateKey.unhexlify('a12618ff6540dcd79bf68fda2faf0589b672e18b99a1ebcc32a40a67acdab608')
>>> p2pkh_solver = P2pkhSolver(privk)
```

now let's assume we have an unsigned mutable transaction, we will use this solver to fill in the transaction's
scriptSig:

```python
>>> unsigned_tx = MutableTransaction(...)
>>> previous_txout = TxOut(value=1000, n=0, script_pubkey=p2pkh_script)
>>> signed_tx = unsigned_tx.spend([previous_txout], [p2pkh_solver])
```

### P2SH
Creating a P2SH script that embeds a P2PKH script:

```python
>>> p2sh_script = P2shScript(P2pkhScript(pubk))
>>> p2sh_script.hexlify()
'a914cd1ab43e7c01a08886fd0e699988d2f44c9c57cc87'
>>> str(p2sh_script)
'OP_HASH160 cd1ab43e7c01a08886fd0e699988d2f44c9c57cc OP_EQUAL'
```

A solver to spend it would be:

```python
>>> privk = PrivateKey.unhexlify('a12618ff6540dcd79bf68fda2faf0589b672e18b99a1ebcc32a40a67acdab608')
>>> solver = P2shSolver(P2pkhScript(pubk),  # the redeemScript
                        P2pkhSolver(privk)) # the redeemScript's solver
```

### P2WSH
Creating a P2WSH script that embeds a P2PKH script:

```python
>>> p2wsh_script = P2wshV0Script(P2pkhScript(pubk))
>>> p2wsh_script.hexlify()
'002058f04cd072784e9dede6821772a195cef65424f2e4957e14232e642bbbdf1aec'
>>> str(p2wsh_script)
'OP_0 58f04cd072784e9dede6821772a195cef65424f2e4957e14232e642bbbdf1aec'
```

Solving it:

```python
>>> solver = P2wshV0Solver(P2pkhScript(pubk),  # witness script
...                        P2pkhSolver(privk)) # witness script's solver
```

### P2WSH-over-P2SH
Let's now create a P2SH scriptPubKey that embeds a P2WSH that, in turn, embeds
a P2PKH:

```python
>>> p2wsh_over_p2sh = P2shScript(P2wshV0Script(P2pkhScript(pubk)))
>>> p2wsh_over_p2sh.hexlify()
'a914efbd1b969b0e15e7a3dc9b1128e4cf493974e62187'
>>> str(p2wsh_over_p2sh)
'OP_HASH160 efbd1b969b0e15e7a3dc9b1128e4cf493974e621 OP_EQUAL'
>>> solver = P2shSolver(
...              P2wshV0Script(P2pkhScript(pubk)),   # redeemScript
...              P2wshV0Solver(            # redeemScript solver
...                  P2pkhScript(pubk),    # witnessScript
...                  P2pkhSolver(privk)    # witnessScript solver
...              )
...           )
```

### P2PK

```python
>>> p2pk_script = P2pkScript(pubk)
>>> p2pk_script.hexlify()
'21025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260ac'
>>> str(p2pk_script)
'025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260 OP_CHECKSIG'
>>> solver = P2pkSolver(privk)
```

### Multisig

```python
>>> privk2 = PrivateKey.unhexlify('710b464f020b676fd9ec3af28d014dec9c8582e6a9059731a3e14aa762527ae4')
>>> pubk2 = privk2.pub()
>>> multisig_script = MultisigScript(1, pubk, pubk2, 2)  # a 1-of-2 multisig
>>> multisig_script.hexlify()
'5121025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe882602102a5f22a78db5c38eaa18f73390e82e000bd52ab84edbcb3ad9b4124460acaf5ee52ae'
>>> str(multisig_script)
'OP_1 025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260 02a5f22a78db5c38eaa18f73390e82e000bd52ab84edbcb3ad9b4124460acaf5ee OP_2 OP_CHECKMULTISIG'
>>> multisig_solver = MultisigSolver(privk)  # this could potentially be passed a list of SIGHASHES in the end to use them when signing
```

As one will usually embed this in a P2SH format, this could be done as follows:

```python
>>> p2sh_multisig = P2shScript(multisig_script)
>>> solver = P2shSolver(multisig_script, multisig_solver)
```

### Timelocks, Hashlocks, IfElse
Now we are going to create a very complex output. This output can be spent in two ways:
1. at any time, with two out of two signatures
2. 5 blocks after it has entered a block, with only one signature.
This script is hence composed of two possible execution flows: an `if` branch and
an `else` branch. Inside the first branch, a 2-of-2 multisig script can be found.
Inside the second branch there is a timelocked script. Such a script has a time
(a relative time in this case, expressed as a `Sequence` number) and an inner script,
which is the one that can be executed after the relative time has expired.
We can create such a script in the following way:

```python
>>> timelocked_multisig = IfElseScript(
...     # if branch
...     MultisigScript(  # a multisig script, as above
...         2,
...         pubk,
...         pubk2,
...         2
...     ),
...     # else branch
...     RelativeTimelockScript(  # timelocked script
...         Sequence(5),  # expiration, 5 blocks
...         P2pkhScript(  # locked script
...             pubk
...         )
...     )
... )
```

Let's see this script a bit more in depth:

```python
>>> timelocked_multisig.type
'if{ multisig }else{ [relativetimelock] p2pkh }'
>>> str(timelocked_multisig)
'OP_IF OP_2 025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260 02a5f22a78db5c38eaa18f73390e82e000bd52ab84edbcb3ad9b4124460acaf5ee OP_2 OP_CHECKMULTISIG OP_ELSE OP_5 OP_CHECKSEQUENCEVERIFY OP_DROP OP_DUP OP_HASH160 905f77004d081f20dd421ba5288766d56724c3b2 OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF'
>>> timelocked_multisig.if_script
MultisigScript(2, 025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260, 02a5f22a78db5c38eaa18f73390e82e000bd52ab84edbcb3ad9b4124460acaf5ee, 2)
>>> str(timelocked_multisig.if_script)
'OP_2 025f628d7a11ace2a6379119a778240cb70d6e720750416bb36f824514fbe88260 02a5f22a78db5c38eaa18f73390e82e000bd52ab84edbcb3ad9b4124460acaf5ee OP_2 OP_CHECKMULTISIG'
>>> timelocked_multisig.else_script
RelativeTimelockScript(5, OP_DUP OP_HASH160 905f77004d081f20dd421ba5288766d56724c3b2 OP_EQUALVERIFY OP_CHECKSIG)
>>> str(timelocked_multisig.else_script)
'OP_5 OP_CHECKSEQUENCEVERIFY OP_DROP OP_DUP OP_HASH160 905f77004d081f20dd421ba5288766d56724c3b2 OP_EQUALVERIFY OP_CHECKSIG'
>>> timelocked_multisig.else_script.locked_script
P2pkh(905f77004d081f20dd421ba5288766d56724c3b2)
>>> timelocked_multisig.else_script.locked_script.decompile()
'OP_DUP OP_HASH160 905f77004d081f20dd421ba5288766d56724c3b2 OP_EQUALVERIFY OP_CHECKSIG'
```

Let's write the solvers for this script:

```python
>>> solver_if = IfElseSolver(Branch.IF,                      # branch selection
...                          MultisigSolver(privk, privk2))  # inner solver
>>> solver_else = IfElseSolver(Branch.ELSE,
...                            TimelockSolver(P2pkhSolver(privk)))
```

### Low-level signing
If one wants to sign a transaction by hand, instead of using solvers, one of the following procedures can be used:

* Manually writing the scriptSig (this can be seen in the **Creating transactions** section)
* Creating the scriptSig by computing and signing the digest of the transaction

Let's see an example of this last case:

```python
>>> unsigned = MutableTransaction(...)
>>> digest = unsigned.get_digest(2,   # the input to be signed
                                 prev_script,  # the previous script to spend (this is the redeem/witness script in case of P2SH/P2WSH ouputs)
                                 sighash=Sighash('NONE', anyonecanpay=True))  # sighash: 0x02 | 0x80
>>> privk.sign(digest)
```

In case one wants to sign a SegWit digest for the transaction, the following can be done:

```python
>>> unsigned = SegWitTransaction(...)
>>> digest = unsigned.get_segwit_digest(2,   # the input to be signed
                                        prev_script,  # the previous script to spend (this is the redeem/witness script in case of P2SH/P2WSH ouputs)
                                        prev_amount,  # the amount of the output being spent
                                        sighash=Sighash('NONE', anyonecanpay=True))  # sighash: 0x02 | 0x80
>>> privk.sign(digest)
```

# Contributing and running tests
This library has two testing tools that can be found in the `tests/` folder:
* `unit.py`, this runs basic unit testing
* `integration.py`, this runs tests of signed transactions, to do this, transactions are signed and
sent to a Bitcoin Core node through the `sendrawtransaction` command.

To make sure these tests are using the code in the current repository and not a stale copy installed
in a virtualenv or system wide, please make sure to run the following commands _from the root of the
repo_:

```
python3 -m unittest tests/unit.py
python3 -m unittest tests/integration.py
```

Contributors are invited to run these tests before submitting PRs. Also, contributions to improve and
expand these tests are highly welcome.

# Roadmap to v1
This library's stable version 1 will be released once the following changes are made:
* More efficient script matching (i.e. scripts should be able to specify fast matching conditions
instead of trying to parse the raw bytes to decide whether the template is matched)
* Caching on SegWit digest computation to avoid quadratic hashing
* Generation of private keys through secure entropy sources
* An extensive documentation of all modules, classes and their parameters is produced

# TODO
Since this library is still a work in progress, the following roadmap lists the improvements to be
done eventually:
* Expanding the test suites
* Adding docstrings where missing (many places)
* Handling `OP_CODESEPARATOR`s  in the signing process
* Add further transaction creation helpers
* Add RPC calls to Bitcoin Core nodes
* Add networking with Bitcoin Core nodes

# Acknowledgements
Special thanks to [gdecicco](https://github.com/gdecicco) and [lorenzogiust](https://github.com/lorenzogiust)
for contributing with performance improvements and general review.
