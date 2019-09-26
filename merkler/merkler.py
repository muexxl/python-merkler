import hashlib
import json
import binascii

class Merkler(object):

    def __init__(self):
        self.merkle_tree = []
        hashes=[]
        self.merkle_tree.append(hashes)

    def addHash(self, data):
        if not self.isHash(data):
            raise Exception ("Merkler.add_hash was called with non hash data")
        self.merkle_tree[0].append(data)


    def BuildMerkleTree(self):
        self.merkle_tree=self.merkle_tree[:1] # remove previous merkle tree entries, if any
        hashes = self.merkle_tree[0][:] #get base level

        while len(hashes) > 1: #check if highest level is reached
            hashes = self.CalculateNextMerkleTreeLevel(hashes)[:]
            self.merkle_tree.append(hashes)

    def CalculateNextMerkleTreeLevel(self, hashes):
        current_level_hashes = hashes[:]
        next_level_hashes=[]

        if len(current_level_hashes)%2 == 1: # extend hashes if number of entries is odd
            current_level_hashes.append(current_level_hashes[-1])

        while len(current_level_hashes) >=2:
            hash1 = current_level_hashes.pop(0)
            hash2 = current_level_hashes.pop(0)
            next_hash = self.calcHash(hash1 + hash2)
            next_level_hashes.append(next_hash)

        return next_level_hashes

    def addFile(self, filename):
        sha256_hash = hashlib.sha256()
        with open(filename,"rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        fileHash=sha256_hash.digest()
        self.addHash(fileHash)
        return binascii.hexlify(fileHash).decode('utf-8')

    def exportMerkleTreeAsString(self):
        string_merkle_tree=[]
        for level in self.merkle_tree:
            string_level=[]
            for hash in level:
                string_level.append(hash.hex())
            string_merkle_tree.append(string_level[:])
        return string_merkle_tree

    def exportMerkleTreeAsJSON(self):
        json_string=json.dumps(self.exportMerkleTreeAsString())
        return json_string

    def saveAsJSONFile(self, filename):
        jstring = self.exportMerkleTreeAsJSON()
        with open(filename, 'w') as f:
            f.write(jstring)

    def loadFromJSONFile(self, filename):
        with open(filename, 'w') as f:
            jstring=f.read()
        self.importMerkleTreeFromJSON(jstring)
        return self.verify()

    def importMerkleTreeFromJSON(self, json_string):
        string_merkle_tree=json.loads(json_string)
        self.importMerkleTreeFromString(string_merkle_tree)

    def importMerkleTreeFromString(self, string_merkle_tree):
        merkle_tree = []
        for hashes_as_string in string_merkle_tree:
            hashes=[]
            for hash_as_string in hashes_as_string:
                hashes.append(binascii.unhexlify(hash_as_string.encode()))
            merkle_tree.append(hashes[:])
        self.merkle_tree = merkle_tree

    def verify(self):
        m=Merkler()
        m.merkle_tree[0]=self.merkle_tree[0][:]
        m.BuildMerkleTree()
        result= m.merkle_tree[-1][0] == self.merkle_tree[-1][0]

        return result

    def getMerkleBranch(self, target_hash):
        try:
            position=self.merkle_tree[0].index(target_hash)
        except ValueError:
            print ('Hash not found in current Merkle tree')

        mb = MerkleBranch()
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

    def isHash(self, data):

        result = True

        if not type(data) == bytes:
            result= False
        elif not len(data) == 32:
            result= False

        return result

    def calcHash(self, data):
        return hashlib.sha256(data).digest()

class MerkleBranch(object):

    def __init__(self):
        self.startHash= b''
        self.startHashPosition = 0
        self.merkleRootHash=b''
        self.hashes = []

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

    def exportAsJSON(self):
        mb={
            'startHash': binascii.hexlify(self.startHash).decode('utf-8'),
            'startHashPosition' :self.startHashPosition,
            'hashes': [binascii.hexlify(hash).decode('utf-8') for hash in self.hashes],
            'merkleRootHash' : binascii.hexlify(self.merkleRootHash).decode('utf-8')
        }

        return json.dumps(mb)

    def loadFromJSON(self, json_string):
        mb=json.loads(json_string)
        self.startHash= binascii.unhexlify(mb['startHash'].encode())
        self.startHashPosition = mb['startHashPosition']
        self.merkleRootHash=binascii.unhexlify(mb['merkleRootHash'].encode())
        self.hashes = [binascii.unhexlify(hashstring.encode()) for hashstring in mb['hashes']]

    def saveAsJSONFile(self, filename):
        jstring = self.exportAsJSON()
        with open(filename, 'w') as f:
            f.write(jstring)


    def loadFromJSONFile(self, filename):
        with open(filename, 'r') as f:
            jstring=f.read()
        self.loadFromJSON(jstring)
        return self.verify()
