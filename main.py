from datetime import datetime as dt
from helpers import *
import hashlib
import json
import base64

MINING_REWARD = 100


class Blockchain:

    def __init__(self, address, publickey):
        self.blocks = []
        self.miner_login = {
            "address": address,
            "publickey": publickey
        }
        self.pending_transactions = []
        self.difficulty = 3
        self.add_genesis_block()

    def add_transaction(self, tx):
        self.pending_transactions.append(tx)
        return None

    def add_block(self):
        previous_hash = self.get_previous_hash()
        block = Block(self.pending_transactions, previous_hash)
        self.mine_block(block)
        self.blocks.append(block)
        self.reset_transaction_log()
        self.add_mining_reward(MINING_REWARD)
        return None
        
    def add_genesis_block(self):
        block = Block([], "0")
        self.mine_block(block)
        self.blocks.append(block)
        self.reset_transaction_log()
        self.add_mining_reward(MINING_REWARD)
        return None

    def get_previous_hash(self):
        return self.blocks[-1].data["block_hash"]

    def verify_blockchain(self):
        for i in range(1, len(self.blocks)):
            previous_hash = self.blocks[i].data["previous_hash"]
            computed_hash = self.blocks[i - 1].compute_block_hash()
            if computed_hash != previous_hash:
                return False
        for block in self.blocks:
            if not self.verify_block_transactions(block):
                return False
        return True

    def mine_block(self, block):
        mined = False
        while not mined:
            block_hash = block.data["block_hash"]
            if block_hash[:self.difficulty] == "0" * self.difficulty:
                mined = True
            else:
                block.update_block_hash()
        print("Mining took {} attempts...".format(block.data["nonce"] + 1))
        return None

    def update_mining_difficulty(self, difficulty):
        self.difficulty = difficulty
        return None

    @staticmethod
    def get_block_data(block):
        data = {
                "block_hash": block.data["block_hash"],
                "nonce": block.data["nonce"],
                "previous_hash": block.data["previous_hash"],
                "tx_list": [tx.data for tx in block.data["tx_list"]]
            }
        return data

    @staticmethod
    def verify_transaction(tx):
        publickey = RSA.importKey(tx.data["publickey"])
        data = tx.data["hash"].encode()
        signature = tx.data["signature"]
        return publickey.verify(data, (int(base64.b64decode(signature)),))

    def verify_block_transactions(self, block):
        true_tx = [self.verify_transaction(tx) for tx in block.data["tx_list"]]
        if all(true_tx):
            return True
        else:
            return False

    def reset_transaction_log(self):
        self.pending_transactions = []
        return None

    def add_mining_reward(self, reward):
        reward_store = create_user()
        new_tx = Transaction(
            reward_store["address"], self.miner_login["address"], reward,
            reward_store["publickey"], reward_store["privatekey"])
        self.pending_transactions.append(new_tx)
        return None

    def __str__(self):
        data = [self.get_block_data(block) for block in self.blocks]
        return json.dumps(data, indent=2)

    def __repr__(self):
        data = [self.get_block_data(block) for block in self.blocks]
        return json.dumps(data, indent=2)


class Block:

    def __init__(self, tx_list, previous_hash):
        self.data = {
            "nonce": 0,
            "previous_hash": previous_hash,
            "tx_list": tx_list
        }
        self.data["block_hash"] = self.compute_block_hash()

    def compute_block_hash(self):
        payload = "|".join([tx.compute_hash() for tx in self.data["tx_list"]])
        payload += str(self.data["nonce"])
        current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return current_hash

    def update_block_hash(self):
        self.data["nonce"] += 1
        self.data["block_hash"] = self.compute_block_hash()
        return None

    def __str__(self):
        data = {
            "block_hash": self.data["block_hash"],
            "nonce": self.data["nonce"],
            "previous_hash": self.data["previous_hash"],
            "tx_list": [tx.data for tx in self.data["tx_list"]]
        }
        return json.dumps(data, indent=2)

    def __repr__(self):
        data = {
            "block_hash": self.data["block_hash"],
            "nonce": self.data["nonce"],
            "previous_hash": self.data["previous_hash"],
            "tx_list": [tx.data for tx in self.data["tx_list"]]
        }
        return json.dumps(data, indent=2)


class Transaction:

    def __init__(self, from_address, to_address, amount, publickey, privatekey):
        self.data = {
            "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "from_address": from_address,
            "to_address": to_address,
            "amount": amount,
            "publickey": publickey.exportKey().decode()
        }
        self.payload = self.get_payload()
        self.data["hash"] = self.compute_hash()
        self.data["signature"] = self.sign(privatekey).decode()

    def get_payload(self):
        data = [self.data["timestamp"],
                self.data["from_address"],
                self.data["to_address"],
                str(self.data["amount"])]

        return "|".join(data)

    def compute_hash(self):
        payload = self.get_payload()
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def sign(self, privatekey):
        message = str((privatekey.sign(self.data["hash"].encode(), ''))[0])
        return base64.b64encode(message.encode())

    def __str__(self):
        return json.dumps(self.data, indent=2)

    def __repr__(self):
        return json.dumps(self.data, indent=2)


def main():

    miner = create_user()
    user1 = create_user()
    user2 = create_user()
    user3 = create_user()

    blockchain = Blockchain(miner["address"], miner["publickey"])

    tx1 = Transaction(user1["address"], user2["address"], 10,
                      user1["publickey"], user1["privatekey"])
    tx2 = Transaction(user2["address"], user3["address"], 20,
                      user2["publickey"], user2["privatekey"])

    blockchain.add_transaction(tx1)
    blockchain.add_transaction(tx2)

    blockchain.add_block()
    blockchain.verify_blockchain()

    tx1 = Transaction(user3["address"], user1["address"], 0.001,
                      user3["publickey"], user3["privatekey"])
    tx2 = Transaction(user2["address"], user1["address"], 200,
                      user2["publickey"], user2["privatekey"])
    tx3 = Transaction(user3["address"], user2["address"], 50,
                      user3["publickey"], user3["privatekey"])

    blockchain.add_transaction(tx1)
    blockchain.add_transaction(tx2)
    blockchain.add_transaction(tx3)

    blockchain.add_block()
    blockchain.verify_blockchain()
    
    return None


if __name__ == "__main__":
    main()
