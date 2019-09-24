import hashlib
import json

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

    def is_hash(self, data):

        result = True

        if not type(data) == bytes:
            result= False
        elif not len(data) == 32:
            result= False

        return result

    def calc_hash(self, data):
        return hashlib.sha256(data).digest()
