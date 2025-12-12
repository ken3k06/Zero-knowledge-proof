from sage.all import * 
import random 
from Crypto.Util.number import getPrime
import hashlib 
class Verifier:
    def __init__(self, g, p , y):
        self.g = g 
        self.p = p 
        self.y = y # y = g^x 
        self.u = None # commitment u = g^r 
        Fp = GF(self.p)
        self.q = Fp(self.g).multiplicative_order() 
    def set_commitment(self,u):
        self.u = u % self.p 
    def challenge(self):
        if self.u is None: 
            raise ValueError("commitment is not provide yet")
        payload = str(int(self.g)).encode() + b'|' + str(int(self.p)).encode() + b'|' + \
        str(int(self.y)).encode() + b'|' +str(int(self.u)).encode()
        h = hashlib.sha256(payload).digest()
        self.c = int.from_bytes(h, byteorder='big') % self.q
        return self.c 
    def verify_proof(self, proof):
        if self.u is None: 
            return False 
        proof = proof % self.q 
        c = self.challenge()
        g_z = pow(self.g, proof, self.p)
        y_c = (self.u * pow(self.y, c, self.p)) % self.p
        if g_z == y_c:
            return ("Verified")
        else:
            return ("Not Verified")
class Prover: 
    def __init__(self, x, p, g):
        self.x = x 
        self.p = p 
        self.g = g 
        self.r = None
        Fp = GF(self.p)
        self.q = int(Fp(self.g).multiplicative_order())

    def send_commitment(self):
        self.r = random.randint(1,self.q-1)
        return pow(self.g,self.r,self.p)
    @property 
    def y(self):
        return pow(self.g,self.x,self.p) 
    def respond(self,c):
        c = c % self.q 
        return (self.r+c*self.x) % self.q 
# test 
if __name__ == "__main__":
    p = getPrime(64)
    g = 2 
    x = random.randint(1,p-2)
    prover = Prover(x,p,g)
    print(prover.y)
    verifier = Verifier(g,p,prover.y)
    u = prover.send_commitment()
    verifier.set_commitment(u)
    c = verifier.challenge() 
    proof = prover.respond(c)
    print(verifier.verify_proof(proof))
