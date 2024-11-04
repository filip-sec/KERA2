import copy
import sqlite3

import constants as const
import objects

# get expanded object for 
def fetch_object(oid, cur):
    cur.execute("SELECT * FROM objects WHERE id=?", (oid,))
    row = cur.fetchone()
    if row:
        return objects.Object(row)
    return None

# get utxo for block
def fetch_utxo(bid, cur):
    cur.execute("SELECT utxo FROM blocks WHERE id=?", (bid,))
    row = cur.fetchone()
    if row:
        return row[0]
    return None

# returns (blockid, intermediate_blocks)
def find_lca_and_intermediate_blocks(tip, blockids):
    # This is a placeholder implementation
    return tip, blockids

# return a list of transactions by index
def find_all_txs(txids, cur):
    txs = [] 
    for txid in txids:
        tx = fetch_object(txid, cur)
        if tx:
            txs.append(tx)
    return txs

# return a list of transactions in blocks
def get_all_txids_in_blocks(blocks):
    txids = []
    for block in blocks:
        txids.extend(block.txids)
    return txids

# get (id of lca, list of old blocks from lca, list of new blocks from lca) 
def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    lca, intermediate_blocks = find_lca_and_intermediate_blocks(old_tip, [new_tip])
    old_blocks = intermediate_blocks[:intermediate_blocks.index(lca)]
    new_blocks = intermediate_blocks[intermediate_blocks.index(lca)+1:]
    return lca, old_blocks, new_blocks

def rebase_mempool(old_tip, new_tip, mptxids):
    lca, old_blocks, new_blocks = get_lca_and_intermediate_blocks(old_tip, new_tip)
    old_txids = get_all_txids_in_blocks(old_blocks)
    new_txids = get_all_txids_in_blocks(new_blocks)
    mptxids = [txid for txid in mptxids if txid not in old_txids]
    mptxids.extend(new_txids)
    return mptxids

class Mempool:
    def __init__(self, bbid: str, butxo: dict):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []

    def try_add_tx(self, tx: dict) -> bool:
        if tx['id'] not in self.txs:
            self.txs.append(tx['id'])
            return True
        return False

    def rebase_to_block(self, bid: str):
        self.txs = rebase_mempool(self.base_block_id, bid, self.txs)
        self.base_block_id = bid