import hashlib 
import os
import random 
import itertools
from ast import literal_eval 

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']
db = list()
for i in range(len(VALUES)):
    for j in range(len(SUITS)):
        db.append(VALUES[i] + '_' + SUITS[j])
print(db)
class ZKProof:
    global db 
    def __init__(self):
        self.db = db 
        self.salt = os.urandom(16)
    def _hash(self, x): 
        return hashlib.sha256(x.encode('utf-8') + self.salt).hexdigest()
    def get_secret(self):
        return self.secret 
    def gen_proof(self, secret):
        self.secret = secret
        self.v = self._hash(secret)
        r = str(random.randint(1,len(self.db)))
        self.x = self._hash(r)
        return self.x 
    def verify(self, response):
        diff = list(set(self.db)-set(response))
        if len(diff) != 1:
            return False 
        s = diff[0]
        return self._hash(s) == self.v 
zkp = ZKProof()
secret_card = random.choice(db)
print(secret_card)
x = zkp.gen_proof(secret_card)
print('Proof:', x)

s = input("Give me the proof: ")
cards = literal_eval(s)
print(zkp.verify(cards))

    
