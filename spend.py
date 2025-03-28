import hashlib
from ecdsa import SigningKey, SECP256k1, util
from typing import List
from balance import (
    EXTENDED_PRIVATE_KEY,
    bcli,
    get_pub_from_priv,
    get_p2wpkh_program,
    recover_wallet_state)
SEQUENCES=b'\xff\xff\xff\xff'
LOCKTIME=b'\x00\x00\x00\x00'


def compact_size(data) -> bytes:
    length = len(data)
    if length <= 0xfc:
        return length.to_bytes(1, 'big')
    elif length <= 0xffff:
        return b'\xfd' + length.to_bytes(2, 'little')
    elif length <= 0xffffffff:
        return b'\xfe' + length.to_bytes(4, 'little')
    elif length <= 0xffffffffffffffff:
        return b'\xff' + length.to_bytes(8, 'little')



# Given 2 compressed public keys as byte arrays, construct
# a 2-of-2 multisig output script. No length byte prefix is necessary.
def create_multisig_script(keys: List[bytes]) -> bytes:
    if (len(keys) < 2):
        raise ValueError("Cannot create a 2 of 2 multisig form less than 2 keys")
    key0 = bytes.fromhex(keys[0])
    key1 = bytes.fromhex(keys[1])
    return b'\x52' + compact_size(key0) + key0 + compact_size(key1) + key1 +  b'\x52\xae'

# Given an output script as a byte array, compute the p2wsh witness program
# This is a segwit version 0 pay-to-script-hash witness program.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
def get_p2wsh_program(script: bytes, version: int=0) -> bytes:
    return  b'\x00\x20' + hashlib.sha256(script).digest()


# Given an outpoint, return a serialized transaction input spending it
# Use hard-coded defaults for sequence and scriptSig
def input_from_utxo(txid: bytes, index: int) -> bytes:
    if(len(txid) != 32):
        raise ValueError("Invalid transaction id")
    scriptSig=b'\x00'
    index_byte = int.to_bytes(index, 4, 'little')
    return txid + index_byte + scriptSig + SEQUENCES


# Given an output script and value (in satoshis), return a serialized transaction output
def output_from_options(script: bytes, value: int) -> bytes:
    value_byte = int.to_bytes(value, 8, 'little')
    script_length = compact_size(script)
    return value_byte + script_length + script
    

# Given a JSON utxo object, extract the public key hash from the output script
# and assemble the p2wpkh scriptcode as defined in BIP143
# <script length> OP_DUP OP_HASH160 <pubkey hash> OP_EQaUALVERIFY OP_CHECKSIG
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
def get_p2wpkh_scriptcode(utxo: object) -> bytes:
    if 'scriptPubKey' in utxo and 'hex' in utxo['scriptPubKey']:
        wit_prog = utxo['scriptPubKey']['hex']
        if not wit_prog.startswith('0014'):
            raise ValueError("Invalid witness program")
        wit_prog = wit_prog[4:]
        return b'\x19\x76\xa9\x14' + bytes.fromhex(wit_prog) + b'\x88\xac'
    else:
        raise ValueError("Invlid Utxo Structure")


# Compute the commitment hash for a single input and return bytes to sign.
# This implements the BIP 143 transaction digest algorithm
# https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification
# We assume only a single input and two outputs,
# as well as constant default values for sequence and locktime
def get_commitment_hash(outpoint: bytes, scriptcode: bytes, value: int, outputs: List[bytes]) -> bytes:
    def dsha256(data: bytes) -> bytes:
        return hashlib.new("sha256", hashlib.new("sha256", data).digest()).digest()
    # Version
    version = (2).to_bytes(4, 'little')
    # All TX input outpoints (only one in our case)
    hashprevout= dsha256(outpoint)
    # All TX input sequences (only one for us, always default value)
    hashsequence = dsha256(SEQUENCES)
    # Single outpoint being spent

    # Scriptcode (the scriptPubKey in/implied by the output being spent, see BIP 143)
    # Value of output being spent
    value_bytes = value.to_bytes(8, 'little')
    # Sequence of output being spent (always default for us)
    sequence = SEQUENCES
    # All TX outputs
    outputs_hash = dsha256(b''.join(outputs))

    # Locktime (always default for us)
    locktime = LOCKTIME
    # SIGHASH_ALL (always default for us)
    sighash_all = (1).to_bytes(4, 'little')

    pre_image = version + hashprevout + hashsequence + outpoint + scriptcode + \
            value_bytes + sequence + outputs_hash + locktime + sighash_all
    return dsha256(pre_image)

# Given a JSON utxo object and a list of all of our wallet's witness programs,
# return the index of the derived key that can spend the coin.
# This index should match the corresponding private key in our wallet's list.
def get_key_index(utxo: object, programs: List[str]) -> int:
    if not ('scriptPubKey' in utxo and 'hex' in utxo['scriptPubKey']):
        raise ValueError("Invalid Utxo object")
    wit_prog = utxo['scriptPubKey']['hex']
    for index, program in enumerate(programs):
        if program == wit_prog:
            return index
    raise ValueError("Can't find index in programs list")

# Given a private key and message digest as bytes, compute the ECDSA signature.
# Bitcoin signatures:
# - Must be strict-DER encoded
# - Must have the SIGHASH_ALL byte (0x01) appended
# - Must have a low s value as defined by BIP 62:
#   https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#user-content-Low_S_values_in_signatures
def sign(priv: bytes, msg: bytes) -> bytes:
    # Keep signing until we produce a signature with "low s value"
    # We will have to decode the DER-encoded signature and extract the s value to check it
    # Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

    signing_key = SigningKey.from_string(priv, curve=SECP256k1)
    
    while True:
        # Create a deterministic signature
        der_signature = signing_key.sign_digest(
            msg, sigencode=util.sigencode_der_canonize
        )
        
        # Decode the DER signature
        r, s = util.sigdecode_der(der_signature, signing_key.curve.order)
        
        # Ensure low s value
        if s <= signing_key.curve.order // 2:
            break
    
    # Append the SIGHASH_ALL byte
    sighash_all = b'\x01'
    return der_signature + sighash_all

# Given a private key and transaction commitment hash to sign,
# compute the signature and assemble the serialized p2pkh witness
# as defined in BIP 141 (2 stack items: signature, compressed public key)
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#specification
def get_p2wpkh_witness(priv: bytes, msg: bytes) -> bytes:
    signature = sign(priv, msg)
    pubkey = get_pub_from_priv(priv)
    stack_item = b'\x02'
    signature_size = compact_size(signature)
    pubkey_size = compact_size(pubkey)
    witness = stack_item + signature_size + signature + pubkey_size + pubkey
    return witness


# Given two private keys and a transaction commitment hash to sign,
# compute both signatures and assemble the serialized p2pkh witness
# as defined in BIP 141
# Remember to add a 0x00 byte as the first witness element for CHECKMULTISIG bug
# https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki
def get_p2wsh_witness(privs: List[bytes], msg: bytes) -> bytes:
    sig1 = sign(privs[0], msg)
    sig2 = sign(privs[1], msg)
    stack_item = b'\x04'
    pubkeys = [get_pub_from_priv(privs[0]).hex(), get_pub_from_priv(privs[1]).hex()]
    redeem_script = create_multisig_script(pubkeys)
    witness = stack_item + b'\x00' + compact_size(sig1) + sig1 + compact_size(sig2) + sig2 + compact_size(redeem_script) +redeem_script
    return witness

# Given arrays of inputs, outputs, and witnesses, assemble the complete
# transaction and serialize it for broadcast. Return bytes as hex-encoded string
# suitable to broadcast with Bitcoin Core RPC.
# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def assemble_transaction(inputs: List[bytes], outputs: List[bytes], witnesses: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    flags = bytes.fromhex("0001")
    input_count=compact_size(inputs)
    serialized_input = b''.join(inputs)
    serialized_output = b''.join(outputs)
    output_count=compact_size(outputs)
    serialized_witness= b''.join(witnesses)
    locktime = (0).to_bytes(4, "little")
    tx = version + flags + input_count + \
            serialized_input + output_count + serialized_output + serialized_witness + locktime
    return tx.hex()


# Given arrays of inputs and outputs (no witnesses!) compute the txid.
# Return the 32 byte txid as a *reversed* hex-encoded string.
# https://developer.bitcoin.org/reference/transactions.html#raw-transaction-format
def get_txid(inputs: List[bytes], outputs: List[bytes]) -> str:
    version = (2).to_bytes(4, "little")
    input_count = compact_size(inputs)
    serialized_input = b''.join(inputs)
    output_count = compact_size(outputs)
    serialized_output = b''.join(outputs)
    locktime = bytes.fromhex("00000000")
    transaction = (
            version + 
            input_count +
            serialized_input +
            output_count +
            serialized_output +
            locktime
            )
    txid = hashlib.sha256(hashlib.sha256(transaction).digest()).digest()
    return txid[::-1].hex()

# Spend a p2wpkh utxo to a 2 of 2 multisig p2wsh and return the txid
def spend_p2wpkh(state: object) -> str:
    FEE = 1000
    AMT = 1000000

        # Choose an unspent coin worth more than 0.01 BTC
        # Create the input from the utxo
        # Reverse the txid hash so it's little-endian
        # Compute destination output script and output
        # Compute change output script and output
        # Get the message to sign
        # Fetch the private key we need to sign with
        # Sign!
        # Assemble
        # Reserialize without witness data and double-SHA256 to get the txid
        # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here

    for keys, values in state['utxo'].items():
        if values['value'] > 0.01001:
            break
    out_txid, index = keys.split(':')
    index = int(index)
    utxo = values;
    keyindex = get_key_index(utxo, state['programs'])
    out_txid = bytes.fromhex(out_txid)[::-1]
    input_code = input_from_utxo(out_txid, index)
    script = create_multisig_script(state['pubs'])
    out_prog = get_p2wsh_program(script)
    value_output = output_from_options(out_prog, AMT)
    input_value = int ( utxo['value'] * 100000000 ) 

    change_prog = get_p2wpkh_program(bytes.fromhex(state['pubs'][0]))
    change_value = input_value - AMT - FEE
    change_output = output_from_options(change_prog, change_value)

    outpoint = out_txid + index.to_bytes(4, 'little')
    script_code= get_p2wpkh_scriptcode(utxo)
    commit_hash = get_commitment_hash(outpoint, script_code, \
                                      input_value, [value_output, change_output])
    priv_key = state['privs'][keyindex]
    witness = get_p2wpkh_witness(priv_key, commit_hash)
    txid = get_txid([input_code], [value_output, change_output])
    final = assemble_transaction([input_code], [value_output, change_output], [witness])

    return txid, final


# Spend a 2-of-2 multisig p2wsh utxo and return the txid
def spend_p2wsh(state: object, txid: str) -> str:
    COIN_VALUE = 1000000
    FEE = 1000
    AMT = 0
    # Create the input from the utxo
    # Reverse the txid hash so it's little-endian

    # Compute change output script and output

    # Get the message to 0000000000000000000000000000000000000000000000000000000000000000sign

    # Sign!

    # Assemble

    # For debugging you can use RPC `testmempoolaccept ["<final hex>"]` here
    txid_byte = bytes.fromhex(txid)[::-1]
    input_code = input_from_utxo(txid_byte, 0)

    # Compute destination output script and output
    name = "Joseph Daniel Damilare"
    output_script = b'\x6a' +  compact_size(name.encode('ascii')) + name.encode('ascii')
    value_output =  output_from_options(output_script, AMT)
    
    change_prog = get_p2wpkh_program(bytes.fromhex(state['pubs'][0]))
    change_value = COIN_VALUE - FEE
    change_output = output_from_options(change_prog, change_value)

    redeem_script = create_multisig_script(state['pubs'])
    script_code = compact_size(redeem_script) + redeem_script
    outpoint = txid_byte + (0).to_bytes(4, "little")

    commit_hash = get_commitment_hash(outpoint, 
                                      script_code, COIN_VALUE, 
                                      [value_output, change_output])
    witness = get_p2wsh_witness(state['privs'], commit_hash)
    finalhex = assemble_transaction([input_code], 
                                    [value_output, change_output],
                                    [witness])
    return finalhex


if __name__ == "__main__":
    # Recover wallet state: We will need all key pairs and unspent coins
    state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
    txid1, tx1 = spend_p2wpkh(state)
    print(tx1)
    tx2 = spend_p2wsh(state, txid1)
    print(tx2)
