import sqlite3
import objects
import constants as const

def main():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        
        # Build database schema
        cur.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id TEXT PRIMARY KEY,
            target TEXT,
            created INTEGER,
            miner TEXT,
            nonce TEXT,
            note TEXT,
            previd TEXT,
            txids TEXT,
            type TEXT
        )
        ''')

        # Preload genesis block
        genesis_block = const.GENESIS_BLOCK
        cur.execute('''
        INSERT INTO blocks (id, target, created, miner, nonce, note, previd, txids, type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            const.GENESIS_BLOCK_ID,
            genesis_block["T"],
            genesis_block["created"],
            genesis_block["miner"],
            genesis_block["nonce"],
            genesis_block["note"],
            genesis_block["previd"],
            ','.join(genesis_block["txids"]),
            genesis_block["type"]
        ))

        con.commit()

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()

if __name__ == "__main__":
    main()
