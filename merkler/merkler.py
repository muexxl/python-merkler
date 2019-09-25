import hashlib
import json
import binascii

class Merkler(object):

    def __init__(self):
        self.merkle_tree = []
        hashes=[]
        self.merkle_tree.append(hashes)

    def add_hash(self, data):
        if not self.is_hash(data):
            raise Exception ("Merkler.add_hash was called with non hash data")
        self.merkle_tree[0].append(data)


    def build_merkle_tree(self):
        self.merkle_tree=self.merkle_tree[:1] # remove previous merkle tree entries, if any
        hashes = self.merkle_tree[0][:] #get base level

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

    def get_merkle_branch(self, target_hash):
        try:
            position=self.merkle_tree[0].index(target_hash)
        except ValueError:
            print ('Hash not found in current Merkle tree')

        mb=MerkleBranch()
        mb.startHashPosition = position
        mb.startHash = target_hash # add starting hash

        for hashes in self.merkle_tree[:-1]:

            if position%2 == 0 :
                neighbor = position + 1
            elif position%2 == 1:
                neighbor = position - 1
            if neighbor == len(hashes): #refer to last entry, if pointer is out of range
                neighbor = position

            mb.hashes.append(hashes[neighbor])

            position=neighbor//2

        mb.merkleRootHash = self.merkle_tree[-1][0] # add merkle root
        return mb

    def is_hash(self, data):

        result = True

        if not type(data) == bytes:
            result= False
        elif not len(data) == 32:
            result= False

        return result

    def calc_hash(self, data):
        return hashlib.sha256(data).digest()

class MerkleBranch(object):
    startHash= b''
    startHashPosition = 0
    merkleRootHash=b''
    hashes = []

    def __init__(self):
        pass

    def verify(self):
        position = self.startHashPosition
        startHash = self.startHash
        currentHash = self.startHash
        for neighborHash in self.hashes:
            if position%2 == 0 :
                leftHash = currentHash
                rightHash= neighborHash
            else :
                leftHash = neighborHash
                rightHash= currentHash

            position = position//2
            data = leftHash + rightHash
            currentHash=hashlib.sha256(data).digest()

        result= currentHash == self.merkleRootHash
        return result

def test():
    data='test'.encode()
    hash=hashlib.sha256(data).digest()

    m=Merkler()
    for i in range(5):
        m.add_hash(hash)
        hash=hashlib.sha256(hash).digest()

    m.build_merkle_tree()
    m.merkle_tree
    mbranch= None
    mbranch=m.get_merkle_branch(m.merkle_tree[0][0])
    mbranch.verify()
    mbranch.startHash
    mbranch.merkleRootHash
    mbranch.startHashPosition
    mbranch.hashes
    mbranch.startHash=b'e\xd0!\xde\xe3=\xdd\x87\xae}\x82@%\xbdY\xd2B7r?`gt\x98Q\xf0\x81\xf5\xde\xc9\x84c'
    position = mbranch['position']
    startHash = mbranch['startHash']
    currentHash = startHash
    for neighborHash in mbranch['hashes'][:]:
        if position%2 == 0 :
            leftHash = currentHash
            rightHash= neighborHash
        else :
            leftHash = neighborHash
            rightHash= currentHash

        position = position//2
        data = leftHash + rightHash
        currentHash=hashlib.sha256(data).digest()

    result= currentHash == mbranch['merkleRootHash']
    print ('Result : {}'.format(result))

    target_hash=m.merkle_tree[0][12].hex()
    m.merkle_tree[0][-1].hex()
    position=m.merkle_tree[0].index(target_hash)
    merkle_branch= {
        'position': position ,
        'hashes':[]
        }
    merkle_tree=m.merkle_tree

    merkle_branch['hashes'].append(merkle_tree[0][position]) # add target hash
    for hashes in merkle_tree[:-1]:
        pass
        if position%2 == 0 :
            neighbor = position + 1
        elif position%2 == 1:
            neighbor = position - 1

        if neighbor == len(hashes): #avoid error if last entry needs to be doubled
            neighbor = position

        merkle_branch['hashes'].append(hashes[neighbor].hex())

        position=neighbor//2

    merkle_branch['hashes'].append(merkle_tree[-1][0]) # add final result


    merkle_json=m.export_merkle_as_json()
    merkle_string=m.export_merkle_as_string()
    m.import_merkle_from_string(merkle_string)
    m.import_merkle_from_json(merkle_json)
    x=json.loads(merkle_json)
    merkle_string==x
    import binascii
    binascii.unhexlify(x[0][0].encode())==m.merkle_tree[0][0]
    b'asdf'*1
