import hashlib
import json
import binascii

class Merkler:

    def __init__(self):
        self.merkle_tree = []
        hashes=[]
        self.merkle_tree.append(hashes)

    def add_hash(self, data):
        if not self.is_hash(data):
            raise Exception ("Merkler.add_hash was called with non hash data")
        self.merkle_tree[0].append(data)

    def build_merkle_tree(self):
        hashes = self.merkle_tree[-1][:]
        while len(hashes) > 1: #check if highest level is reached
            hashes = self.calculate_next_merkle_tree_level(hashes)[:]
            self.merkle_tree.append(hashes)

    def calculate_next_merkle_tree_level(self, hashes):
        current_level_hashes = hashes[:]
        next_level_hashes=[]

        if len(current_level_hashes)%2 == 1: # extend hashes if number of entries is odd
            current_level_hashes.append(current_level_hashes[-1])

        while len(current_level_hashes) >=2:
            hash1 = current_level_hashes.pop(0)
            hash2 = current_level_hashes.pop(0)
            next_hash = self.calc_hash(hash1 + hash2)
            next_level_hashes.append(next_hash)

        return next_level_hashes

    def export_merkle_as_string(self):
        string_merkle_tree=[]
        for level in self.merkle_tree:
            string_level=[]
            for hash in level:
                string_level.append(hash.hex())
            string_merkle_tree.append(string_level[:])
        return string_merkle_tree

    def export_merkle_as_json(self):
        json_string=json.dumps(self.export_merkle_as_string())
        return json_string

    def import_merkle_from_json(self, json_string):
        string_merkle_tree=json.loads(json_string)
        self.import_merkle_from_string(string_merkle_tree)

    def import_merkle_from_string(self, string_merkle_tree):
        merkle_tree = []
        for hashes_as_string in string_merkle_tree:
            hashes=[]
            for hash_as_string in hashes_as_string:
                hashes.append(binascii.unhexlify(hash_as_string.encode()))
            merkle_tree.append(hashes[:])
        self.merkle_tree = merkle_tree

    def is_hash(self, data):

        result = True

        if not type(data) == bytes:
            result= False
        elif not len(data) == 32:
            result= False

        return result

    def calc_hash(self, data):
        return hashlib.sha256(data).digest()


def test():
    data='test'.encode()
    hash=hashlib.sha256(data).digest()

    m=Merkler()
    for i in range(6):
        m.add_hash(hash)
        hash=hashlib.sha256(hash).digest()

    m.build_merkle_tree()
    m.merkle_tree

    merkle_json=m.export_merkle_as_json()
    merkle_string=m.export_merkle_as_string()
    m.import_merkle_from_string(merkle_string)
    m.import_merkle_from_json(merkle_json)
    x=json.loads(merkle_json)
    merkle_string==x
    import binascii
    binascii.unhexlify(x[0][0].encode())==m.merkle_tree[0][0]
    b'asdf'*1
    
