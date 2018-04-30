#EZcipher v0.1
#Made by Tom Gouville
#https://github.com/Any0ne22/EZcipher/

#-*-coding:utf8;-*-
#qpy:3
#qpy:console
import math
import base64
import os
import re
from random import randrange, randint

###Classes/Functions
class CryptoUtils:
    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modInv(self, a, m):
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m
    
    def MillerRabinOptimized(self, n, k):
        #Implementation du test de Miller Rabin issue de http://codes-sources.commentcamarche.net/source/50184-generateur-de-clef-rsa-tres-efficace
        d=(n-1)>>1 # Ici, on met n-1 sous la forme de "d*2^S" ou d est impair
        s=1 #et puisque n-1 est pair on commence directement aves S=1 et d/2 (performance)
        while not d&1 : # on verifie si d est paire ; plus efficace que d%2
            s+=1 #
            d>>=1 # on divise d par deux ; plus efficace que d/=2
        while k : #on verifie autant de fois que k
            k-=1
            a=randrange(1,n) #on genere un chiffre entre 1 et n !!!!! BESOIN d'optimisation !!!!
            if pow(a,d,n)!=1: #si a^d%n!=1 alors n est peut être composé (!=premier)
                while s: #on verifie avec tout les possibilités entre 0 et s-1 compris 
                    s-=1
                    if pow(a,d<<s,n)!=n-1: # si a^(d*2^r)%n!=n-1 alors, n est composé !
                        return False
        return True
    
    def genRandom(self, intSize):
        if(intSize % 8 != 0):
            raise Exception('Bad int size!')
        size = 0
        randomNumber = 0
        while(size != intSize):
            randomBytes = os.urandom(int(intSize/8))
            randomNumber = int.from_bytes(randomBytes, 'big')
            size = len(bin(randomNumber))-2
        return randomNumber
    
    def intToBytes(self, x):
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')

    def toString(self, data):
        sortie = str(data)
        sortie = sortie[2:len(sortie)-1]
        return sortie

class CryptoRSA:
    def __init__(self, keysize = 0):
        self.exposant = 0
        self.modulo = 0
        self.exposantPrive = 0
        self.P = 0
        self.Q = 0
        self.DP = 0
        self.DQ = 0
        self.inverseQ = 0
        self.CU = CryptoUtils()
        
    def GeneratePrime(self, primeSize):
        isPrime = False
        prime = 0
        while(isPrime == False):
            prime = self.CU.genRandom(primeSize)
            if(prime % 2 == 0):
                prime += 1
            isPrime = self.CU.MillerRabinOptimized(prime, 50)
        return prime
    
    def GenerateKeys(self, keySize):
        if(keySize <= 512 or keySize >= 16384 or keySize % 8 != 0):
            raise Exception("Bad key size!")
        self.exposant = 65537
        nombreRSA = 0
        nombre1 = 0
        nombre2 = 0
        
        while(len(bin(nombreRSA))-2 != keySize):
            nombre1 = self.GeneratePrime(keySize / 2)
            nombre2 = self.GeneratePrime(keySize / 2)
            nombreRSA = nombre1 * nombre2
        if(nombre1 > nombre2):
            self.P = nombre1
            self.Q = nombre2
        else:
            self.P = nombre2
            self.Q = nombre1
        self.modulo = nombreRSA
        self.exposantPrive = self.CU.modInv(self.exposant, (self.P - 1) * (self.Q - 1))
        self.DP = self.exposantPrive % (self.P - 1)
        self.DQ = self.exposantPrive % (self.Q - 1)
        self.inverseQ = self.CU.modInv(self.Q, self.P)
        
    def EncryptString(self, clearText):
        tableau = bytearray(clearText.encode('utf8'))
        
        moduloSize = (len(bin(self.modulo))-2)/8
        paddingStringSize = moduloSize - 3 - len(tableau)
        if(len(tableau) > moduloSize - 3):
            raise Exception("Too much data to encrypt!")
        
        arrayToEncrypt = []
        arrayToEncrypt.append(0)
        arrayToEncrypt.append(2)
        
        i = 2
        while(i < paddingStringSize + 2):
            arrayToEncrypt.append(randint(1, 255))
            i += 1
        i += 1
        arrayToEncrypt.append(0)
        
        j = i
        while(j < moduloSize):
            arrayToEncrypt.append(tableau[j - i])
            j += 1
        
        dataToEncrypt = int.from_bytes(arrayToEncrypt, byteorder = 'big')
        
        c = pow(dataToEncrypt, self.exposant, self.modulo)
        return self.CU.toString(base64.b64encode(self.CU.intToBytes(c)))
        
    def DecryptString(self, cipheredText):
        dataToDecrypt = int.from_bytes(bytearray(base64.b64decode(bytearray(cipheredText.encode('utf8')))), 'big')
        SP = pow(dataToDecrypt, self.DP, self.P)
        SQ = pow(dataToDecrypt, self.DQ, self.Q)
        h = self.inverseQ * (SP - SQ)
        if(h == 0 or h > 1):
            h = h % self.P
        else:
            h = self.P - 1 - ((0 - h - 1) % self.P)
        
        m = SQ + (h * self.Q)
        
        dataToParse = self.CU.intToBytes(m)
        
        parsedData = []
        
        if(dataToParse[0] == 2 or dataToParse[0] == 0):
            i = 2
            while(dataToParse[i] != 0):
                i += 1
            i += 1
            
            while(i < len(dataToParse)):
                parsedData.append(dataToParse[i])
                i += 1
        else:
            raise Exception("Bad data!")
        
        sortie = bytearray(parsedData).decode("utf-8")
        return sortie
        
    def ExportBase64PublicKey(self):
        sortie = []
        sortie.append(self.CU.toString(base64.b64encode(self.CU.intToBytes(self.exposant))))
        sortie.append(self.CU.toString(base64.b64encode(self.CU.intToBytes(self.modulo))))
        return sortie
    
    def ExportBase64PrivateKey(self):
        sortie = []
        sortie.append(self.CU.toString(base64.b64encode(self.CU.intToBytes(self.exposant))))
        sortie.append(self.CU.toString(base64.b64encode(self.CU.intToBytes(self.exposantPrive))))
        sortie.append(self.CU.toString(base64.b64encode(self.CU.intToBytes(self.modulo))))
        sortie.append(self.CU.toString(base64.b64encode(self.CU.intToBytes(self.P))))
        sortie.append(self.CU.toString(base64.b64encode(self.CU.intToBytes(self.Q))))
        return sortie

    def ExportPublicKeyString(self):
        clePublique = self.ExportBase64PublicKey()
        sortie = "PublicKey{" + str(clePublique[0]) + ";" + str(clePublique[1]) +"}"
        return sortie

    def ExportPrivateKeyString(self):
        clePrive = self.ExportBase64PrivateKey()
        sortie = "PrivateKey{" + str(clePrive[0]) + ";" + str(clePrive[1]) + ";" + str(clePrive[2]) + ";" + str(clePrive[3]) + ";" + str(clePrive[4]) + "}" 
        return sortie
        
    def ImportBase64PublicKey(self, exposant, modulo):
        self.exposant = int.from_bytes(bytearray(base64.b64decode(bytearray(exposant.encode('utf8')))), 'big')
        self.modulo = int.from_bytes(bytearray(base64.b64decode(bytearray(modulo.encode('utf8')))), 'big')
    
    def ImportBase64PrivateKey(self, exposant, exposantPrive, modulo, p, q):
        self.exposant = int.from_bytes(bytearray(base64.b64decode(bytearray(exposant.encode('utf8')))), 'big')
        self.exposantPrive = int.from_bytes(bytearray(base64.b64decode(bytearray(exposantPrive.encode('utf8')))), 'big')
        self.modulo = int.from_bytes(bytearray(base64.b64decode(bytearray(modulo.encode('utf8')))), 'big')
        self.P = int.from_bytes(bytearray(base64.b64decode(bytearray(p.encode('utf8')))), 'big')
        self.Q = int.from_bytes(bytearray(base64.b64decode(bytearray(q.encode('utf8')))), 'big')
        #if(self.P < self.Q):
        #    raise Exception("Bad key value")
        self.exposantPrive = self.CU.modInv(self.exposant, (self.P - 1) * (self.Q - 1))
        self.DP = self.exposantPrive % (self.P - 1)
        self.DQ = self.exposantPrive % (self.Q - 1)
        self.inverseQ = self.CU.modInv(self.Q, self.P)

    def ImportPublicKeyString(self, cle):
        matches = re.match(r'PublicKey\{([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?)\}', cle)
        if(matches != False):
            self.ImportBase64PublicKey(matches.group(1),matches.group(2))
        else:
            raise Exception("Invalid key")

    def ImportPrivateKeyString(self, cle):
        matches = re.match(r'PrivateKey\{([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?);([a-zA-Z0-9\+\/\=]+?)\}', cle)
        if(matches != False):
            self.ImportBase64PrivateKey(matches.group(1),matches.group(2),matches.group(3),matches.group(4),matches.group(5))
        else:
            raise Exception("Invalid key")
        return 0
        
class CryptoAES:
    def __init__(self, password = 0):
        return 0
