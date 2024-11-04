from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re

import constants as const

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    return bool(OBJECTID_REGEX.match(objid_str))

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    return bool(PUBKEY_REGEX.match(pubkey_str))


SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    return bool(SIGNATURE_REGEX.match(sig_str))

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    return bool(NONCE_REGEX.match(nonce_str))


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    return bool(TARGET_REGEX.match(target_str))


def validate_transaction_input(in_dict):
    required_keys = ["outpoint", "sig"]
    if not all(key in in_dict for key in required_keys):
        return False
    if not validate_objectid(in_dict["outpoint"]):
        return False
    if not validate_signature(in_dict["sig"]):
        return False
    return True

def validate_transaction_output(out_dict):
    required_keys = ["value", "pubkey"]
    if not all(key in out_dict for key in required_keys):
        return False
    if not isinstance(out_dict["value"], int) or out_dict["value"] < 0:
        return False
    if not validate_pubkey(out_dict["pubkey"]):
        return False
    return True

def validate_transaction(trans_dict):
    required_keys = ["inputs", "outputs"]
    if not all(key in trans_dict for key in required_keys):
        return False
    if not isinstance(trans_dict["inputs"], list) or not isinstance(trans_dict["outputs"], list):
        return False
    if not all(validate_transaction_input(in_dict) for in_dict in trans_dict["inputs"]):
        return False
    if not all(validate_transaction_output(out_dict) for out_dict in trans_dict["outputs"]):
        return False
    return True

def validate_block(block_dict):
    required_keys = ["txs", "nonce", "prev_block"]
    if not all(key in block_dict for key in required_keys):
        return False
    if not isinstance(block_dict["txs"], list):
        return False
    if not all(validate_transaction(tx) for tx in block_dict["txs"]):
        return False
    if not validate_nonce(block_dict["nonce"]):
        return False
    if not validate_objectid(block_dict["prev_block"]):
        return False
    return True

def validate_object(obj_dict):
    if "type" not in obj_dict:
        return False
    obj_type = obj_dict["type"]
    if obj_type == "transaction":
        return validate_transaction(obj_dict)
    elif obj_type == "block":
        return validate_block(obj_dict)
    else:
        return False

def get_objid(obj_dict):
    h = hashlib.sha256()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
        public_key.verify(bytes.fromhex(sig), canonicalize(tx_dict))
        return True
    except InvalidSignature:
        return False

class TXVerifyException(Exception):
    pass

def verify_transaction(tx_dict, input_txs):
    if not validate_transaction(tx_dict):
        raise TXVerifyException("Invalid transaction format")
    
    for tx_input in tx_dict["inputs"]:
        outpoint = tx_input["outpoint"]
        if outpoint not in input_txs:
            raise TXVerifyException(f"Referenced transaction {outpoint} not found")
        
        referenced_tx = input_txs[outpoint]
        output_index = int(outpoint.split(":")[1])
        if output_index >= len(referenced_tx["outputs"]):
            raise TXVerifyException(f"Invalid output index {output_index} in referenced transaction {outpoint}")
        
        referenced_output = referenced_tx["outputs"][output_index]
        if not verify_tx_signature(tx_dict, tx_input["sig"], referenced_output["pubkey"]):
            raise TXVerifyException("Invalid signature in transaction input")
    
    return True

class BlockVerifyException(Exception):
    pass

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    fee = 0
    for tx_input in tx["inputs"]:
        outpoint = tx_input["outpoint"]
        if outpoint not in utxo:
            raise TXVerifyException(f"Referenced UTXO {outpoint} not found")
        fee += utxo[outpoint]["value"]
        del utxo[outpoint]
    
    for index, tx_output in enumerate(tx["outputs"]):
        outpoint = f"{get_objid(tx)}:{index}"
        utxo[outpoint] = tx_output
        fee -= tx_output["value"]
    
    if fee < 0:
        raise TXVerifyException("Transaction fee is negative")
    
    return fee

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    if not validate_block(block):
        raise BlockVerifyException("Invalid block format")
    
    if block["prev_block"] != get_objid(prev_block):
        raise BlockVerifyException("Previous block ID does not match")
    
    utxo = copy.deepcopy(prev_utxo)
    total_fee = 0
    for tx in block["txs"]:
        verify_transaction(tx, txs)
        total_fee += update_utxo_and_calculate_fee(tx, utxo)
    
    # Assuming block reward is a constant defined in constants
    block_reward = const.BLOCK_REWARD
    coinbase_tx = block["txs"][0]
    if len(coinbase_tx["outputs"]) != 1 or coinbase_tx["outputs"][0]["value"] != block_reward + total_fee:
        raise BlockVerifyException("Invalid coinbase transaction")
    
    return utxo
