from decimal import Decimal
from ecdsa import SigningKey, SECP256k1
from subprocess import run
from typing import List, Tuple
import hashlib
import hmac
import json

# Provided by administrator
WALLET_NAME = "wallet_079"
EXTENDED_PRIVATE_KEY = "tprv8ZgxMBicQKsPeAbifTfg7bxUcYyxUxNtt4x9ySqwRJxUEiDJKak9EywwGqoHPzvnM5Z65bHJGumiQgt6RGMzi68eCqBpZHW35pcgkvBYRDW"

def parse_path(desc: str) -> List[Tuple [int, bool]]:
    desc = desc.split('/')
    DESC_ARR = []
    for x in desc:
        if x[-1] in {'h', 'H', '\''}:
            DESC_ARR.append((int(x[:-1]) + (1 << 31), True))
        else:
            DESC_ARR.append(( int(x), False ))
    return DESC_ARR;

DESCRIPTOR="84h/1h/0h/0"

def base58_encode(payload: bytes) -> str:
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    count = 0;
    for c in payload:
        if c == 0:
            count += 1;
        else:
            break;

    number = int.from_bytes(payload, byteorder='big');
    one_pref = '1' * count;
    result = ''

    while number > 0:
        number, remainder = divmod(number, 58);
        result = base58_alphabet[remainder] + result;
    return one_pref + result;


def base58check_encode(version: bytes, payload: bytes) -> str:
    total = version + payload;
    check_sum = hashlib.sha256(hashlib.sha256(total).digest()).digest()[:4]
    return base58_encode(total + check_sum)

# Decode a base58 string into an array of bytes
def base58check_decode(base58_string: str) -> bytes:
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    count = 0;
    for c in base58_string:
        if c == '1':
            count += 1
        else:
            break;
    strlen = len(base58_string);
    num = 0;
    # Convert Base58 string to a big integer
    result = 0
    pref = b'\x00' * count;
    for char in base58_string:
        n = base58_alphabet.find(char)
        if n == -1:
            raise ValueError("Invalid character {} in Base58 string".format(
                char))
        result = result * 58 + n;

    # Convert the integer to bytes
    result_bytes = pref + result.to_bytes((result.bit_length()+7)//8, 'big')
    # Chop off the 32 checksum bits and return
    payload, check_sum = result_bytes[:-4], result_bytes[-4:]

    # BONUS POINTS: Verify the checksum!
    calculated_check_sum =  hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] 
    if calculated_check_sum != check_sum:
        raise ValueError("Invalid Checksum")
    return payload;

def base58_decode(base58_string: str) -> bytes:

    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    count = 0;
    for c in base58_string:
        if c == '1':
            count += 1
        else:
            break;
    strlen = len(base58_string);
    num = 0;
    # Convert Base58 string to a big integer
    result = 0
    pref = b'\x00' * count;
    for char in base58_string:
        n = base58_alphabet.find(char)
        if n == -1:
            raise ValueError("Invalid character {} in Base58 string".format(
                char))
        result = result * 58 + n;

    # Convert the integer to bytes
    result_bytes = pref + result.to_bytes((result.bit_length()+7)//8, 'big')
    return result_bytes

def test_base58_function():
    test_vector = [
        ('1M7pXadF9cSthzCdcTVJJQoXGn3jnZshtc',
         '00dcacaf6854482c4e77db1bf5aa5d208c0fb43fad7382cac1'),
        ('mzKicBhFMxLwt6KL8DzRHupQVodYM6tzJ8', 
         '6fce4a637ea786f66c24001fa60bf9460e8f26119c2fd70e6d'),
        ('5J3JAJ2V5sd6HJkukQJqLYyMEdLh6jNb5sVA871CW88HukWngoe',
         '801d8a707714ffeeec0895755897eedd6d9792d0c41f23728e4b8f5ba3f8a5844508aa16c5')
        ]
    fail = False
    for base58_string, decode_string in test_vector:
        result = base58_decode(base58_string).hex()
        if result != decode_string:
            fail = True
            print(f"Error decoding string. Expected result: {decode_string}\nGot {result}")
    if not fail:
        print("Test passed Successfully!!!")

# Deserialize the extended key bytes and return a JSON object
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
def deserialize_key(b: bytes) -> object:
    return {
        "version": b[:4],
        "depth": int.from_bytes(b[4:5], 'big'),
        "fingerprint": b[5:9],
        "child_num": int.from_bytes(b[9:13], 'big'),
        "chaincode": b[13: 13+32],
        "key": b[13+32+1:]
    }



# derive the secp256k1 compressed public key from a given private key
# bonus points: implement ecdsa yourself and multiply you key by the generator point!
def get_pub_from_priv(priv: bytes) -> bytes:
    # print("In get pub")
    # print("priv: ", priv)
    private_key = SigningKey.from_string(priv, curve=SECP256k1)
    public_key = private_key.get_verifying_key().to_string();
    x_part = public_key[:32]
    y_part = public_key[32:]
    prefix = b'\x02' if int.from_bytes(y_part, 'big') % 2 == 0 else b'\x03'
    return prefix + x_part

def int_to_byte(num: int, endianess: str):
    length = (num.bit_length() + 7) //8
    return int.to_bytes(num, length, endianess)


# perform a bip32 parent private key -> child private key operation
# return a json object with "key" and "chaincode" properties as bytes
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-private_parent_key_rarr_private_child_key
def derive_priv_child(key: bytes, chaincode: bytes, index: int, hardened: bool) -> object:
    # print("key: ", key)
    if not hardened or index < (1 << 31):
        pubkey = get_pub_from_priv(key)
        hmac_sha512 = hmac.new(chaincode, pubkey+ index.to_bytes(4, "big"), hashlib.sha512).digest();
    else:
        hmac_sha512 = hmac.new(chaincode, b'\x00' + key + index.to_bytes(4, 'big'),
                               hashlib.sha512).digest()
    il, ir = hmac_sha512[:32], hmac_sha512[32:]

    child_key = (int.from_bytes(key, 'big') + int.from_bytes(il, 'big'))\
                % SECP256k1.order
    child_key = child_key.to_bytes(32, 'big')
    return {"key": child_key, "chaincode": ir}


# given an extended private key and a bip32 derivation path,
# compute the first 2000 child private keys.
# return an array of keys encoded as bytes.
# the derivation path is formatted as an array of (index: int, hardened: bool) tuples.
def get_wallet_privs(key: bytes, chaincode: bytes, path: list[tuple[int, bool]]) -> list[bytes]:
    index = 0
    childkey_arr = []
    # print("key: ", key)
    # print("chaincode: ", chaincode)
    # derivation
    for (x, y) in path:
        # print(f"x: {x}\n y: {y}")
        result = derive_priv_child(key, chaincode, x, y);
        key = result['key']
        chaincode = result['chaincode']

    for i in range(2000):
        result = derive_priv_child(key, chaincode, i, False)
        # key, chaincode = result['key'], result['chaincode']
        # print("in get wallet privs")
        # print("Key: ", key)
        pubkey = get_pub_from_priv(result['key'])
        childkey_arr.append({'priv': result['key'], 'pub': pubkey})
    return childkey_arr

# derive the p2wpkh witness program (aka scriptpubkey) for a given compressed public key.
# return a bytes array to be compared with the json output of bitcoin core rpc getblock
# so we can find our received transactions in blocks.
# these are segwit version 0 pay-to-public-key-hash witness programs.
# https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-p2wpkh
def get_p2wpkh_program(pubkey: bytes, version: int=0) -> bytes:
    pubkey_hash = hashlib.sha256(pubkey).digest()
    pubkey_hash = hashlib.new('ripemd160', pubkey_hash).digest()
    return b'\x00\x14' + pubkey_hash



# assuming bitcoin core is running and connected to signet using default datadir,
# execute an rpc and return its value or error message.
# https://github.com/bitcoin/bitcoin/blob/master/doc/bitcoin-conf.md#configuration-file-path
# examples: bcli("getblockcount")
#           bcli("getblockhash 100")
def bcli(cmd: str):
    # print("cmd ", cmd)
    res = run(
            ["bitcoin-cli", "-signet"] + cmd.split(" "),
            capture_output=True,
            encoding="utf-8")
    if res.returncode == 0:
        return res.stdout.strip()
    else:
        raise Exception(res.stderr.strip())


# recover the wallet state from the blockchain:
# - parse tprv and path from descriptor and derive 2000 key pairs and witness programs
# - request blocks 0-310 from bitcoin core via rpc and scan all transactions
# - return a state object with all the derived keys and total wallet balance
def recover_wallet_state(tprv: str):
    # generate all the keypairs and witness programs to search for

    result = deserialize_key(base58check_decode(tprv))
    wallet_keys = get_wallet_privs(result['key'], result['chaincode'], parse_path(DESCRIPTOR))
    privs = [x['priv'] for x in wallet_keys]
    pubs = [x['pub'].hex() for x in wallet_keys]
    programs = [get_p2wpkh_program(x['pub']).hex() for x in wallet_keys]
    # print(privs, pubs, programs, sep='\n')


    # prepare a wallet state data structure
    state = {
        "utxo": {},
        "balance": Decimal(0),
        "privs": privs,
        "pubs": pubs,
        "programs": programs
    }
    privs, pubs, programs = set(privs), set(pubs), set(programs)
    spent = set()

    # scan blocks 0-300
    height = 300
    for h in range(height + 1):
        blockhash = bcli(f'getblockhash {h}') 
        block = json.loads(bcli(f"getblock {blockhash} 2"), parse_float=Decimal)
        txs = block['tx']
        # scan every tx in every block
        for tx in txs:
            # check every tx input (witness) for our own compressed public keys.
            # these are coins we have spent.
            for inp in tx["vin"]:
                if 'txinwitness' in inp:
                    witness = inp['txinwitness']
                    if len(witness) > 1 and witness[1] in pubs:
                        outpoint = f'{inp["txid"]}:{inp["vout"]}'
                        # print(f"outpoint found: {outpoint}")
                        spent.add(outpoint)
                        if outpoint in state['utxo']:
                            state['balance'] -= Decimal(state['utxo'][outpoint]['value'])
                            del state['utxo'][outpoint]

                    # remove this coin from our wallet state utxo pool
                    # so we do n't double spend it later

            # check every tx output for our own witness programs.
            # these are coins we have received.
            for out in tx["vout"]:
                if "scriptPubKey" in out and "hex" in out["scriptPubKey"]:
                    wit_prog = out["scriptPubKey"]["hex"]

                    if wit_prog in programs:
                        outpoint = f'{tx['txid']}:{out['n']}'
                        value =Decimal(out['value'])
                        # print(f"witness found: {out}")
                        if not outpoint in spent:
                            state["utxo"][outpoint] = out 
                            state["balance"] += value
                    # add to our total balance

                    # keep track of this utxo by its outpoint in case we spend it later
    # print("Finished scanning block")
    return state


if __name__ == "__main__":
    print(f"{WALLET_NAME} {recover_wallet_state(EXTENDED_PRIVATE_KEY)['balance']}")
    # test_base58_function()
