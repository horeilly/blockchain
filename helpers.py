from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib


def rsakeys():
    length = 1024
    privatekey = RSA.generate(length, Random.new().read)
    publickey = privatekey.publickey()
    return privatekey, publickey


def create_user():
    privatekey, publickey = rsakeys()
    address = hashlib.sha1(publickey.exportKey()).hexdigest()
    return {
        "address": address,
        "privatekey": privatekey,
        "publickey": publickey
    }
