from nose.tools import *
import merkler.merkler
import os
import hashlib
import binascii

def setup():
    print ("SETUP!")

def teardown():
    print ("TEAR DOWN !")

def test_basic():
    print ("I RAN")


def create_dummy_files():
    path='tests/dummy_files/'
    if not os.path.exists(path):
        try:
            os.mkdir(path)
        except OSError:
            print ("Creation of the directory %s failed" % path)
    for file in os.listdir(path):
        os.remove(path + file)

    seed='Hasenfruehstueck'.encode()
    data=seed
    for i in range(4):
        hash = hashlib.sha256(data).digest()
        hash_string = binascii.hexlify(hash).decode('utf-8')
        with open( '{}file{:02d}'.format(path,i), 'w') as f:
            f.write(hash_string)

        data=hash

def merkler_add_dummy_files():
    path='tests/dummy_files/'
    if not os.path.exists(path):
        return False
    m=merkler.merkler.Merkler()
    for file in os.listdir(path):
        print(m.addFile(path + file))
    m.BuildMerkleTree()
    m.saveAsJSONFile(path+'_Merkle_tree.json')
