import numpy as np
import random
import math
import olll

# Recommended:
#   n: 32
#   m: 64
#   q: 512
class LWE:

    def __init__(self, n: int, m: int, q: int, A = None, b = None):
        self.n = n
        self.m = m
        self.q = q
        self.A = A
        self.b = b


    def distribution(self) -> int:
        """
        Returns:
            Generates a Value out of a 'small' distribution.
        """

        return random.randint(-2, 2)

    def encrypt(self, bit):
        """
        Args:
            bit: the bit (1 | 0) to be encrypted
        Returns:
            u: the ecrypted matrix
            v: the encrypted Solution vector (with bit)
        """
        r = np.array([self.distribution() for i in range(self.n)])
        e1, e2 = np.array([self.distribution() for i in range(self.m)]), self.distribution()

        u = np.dot(np.transpose(self.A), r) + e1
        v = np.dot(np.transpose(self.b), r) + e2 + (self.q//2 if bit == 1 else 0)


        return u % self.q, v % self.q


    def decrypt(self, u, v, secret):
        """
        Args:
            u: encrypted matrix
            v: encrypted solution vector
            secret: Secret vector to retrieve encrypted bit
        Returns:
            bit: the encrypted bit (0 | 1)
        """

        # u is a vector and v is a scalar
        v1 = np.dot(u, secret) % self.q

        _v = min(abs(v1 - v), self.q - abs(v1 - v))

        return 0 if _v < self.q//4 else 1

    def encryptString(self, word):
        """
        Encrypts a string using LWE bit by bit.

        Args:
            word: The string that's to be encoded.
        
        Returns:
            A list containing pair's of u-v pairs encoding each character (ascii) of {word}
            using 8 bits per character.
        """

        array = np.zeros(shape=(len(word), 8))
        for i in range(len(word)):
            index = 0
            for j in bin(bytearray(word, 'ascii')[i])[2:][::-1]:
                array[i][index] = j
                index += 1

        binary_word = np.reshape(array, 8*len(array))
    
        encrypted = []

        for i in binary_word:
            encrypted.append(self.encrypt(i))
        
        return encrypted

    def decryptString(self, uv_arr, secret):
        """
        Decrypts a list of encrypted u-v pairs and reconstructs the encrypted string out of
        the encrypted bits.
        
        Args:
            uv_arr: An array containing u-v pairs that encrypt a single bit using lwe
            secret: The secret for this lwe
        """

        decrypted = []

        for j in uv_arr:
            decrypted.append(self.decrypt(j[0], j[1], secret))
        
        dec_word = np.reshape(decrypted, (len(decrypted)//8, 8))

        decoded_word = ''
        for i in dec_word:
            char = ''
            for j in range(8):
                char = str(i[j]) + char
            decoded_word += chr(int(char, 2))

        return decoded_word

    def generate(self):
        """
        Generates and saves new A, e, b matrixes/vectors to the object based on n, m, q.

        Args:
            q: mod q
            n: Length of A, e, b
            m: Length of secret

        Returns:
            A: matrix
            b: Solution Vector with error
            e: Error
            secret: Secret vector
        """
        
        A = np.array([
            [random.randint(0, self.q-1) for i in range(self.m)] for j in range(self.n)
        ])

        q8 = self.q//128
        secret = np.array([
            random.randint(-q8, q8) for i in range(self.m)
        ])

        b = np.array([
            np.sum([(A[i][j] * secret[j]) for j in range(self.m)]) % self.q for i in range(self.n)
        ])

        e = np.array([
            self.distribution() for i in range(self.n)
        ])

        b += e

        b %= self.q

        self.A = A
        self.b = b

        return A, b, e, secret


class CrackLWE:

    def __init__(self, lwe):
        self.lwe = lwe

    def crack(self):
        """
        'Crack' the lwe given to 'CrackLWE.class' during initialization.

        Returns:
            error: The error vector of the lwe [n] | None
            secret: The secret vector of the lwe[m] | None
        """

        reduced = self.lll(self)
        return self.findSecret(reduced)

    def lll(self):
        """
        LLL-Algorithm (crack SVP)

        Args:
            A: lwe matrix (length: nxm)
            b: lwe solution vector with error (length: n)
            q: mod q
        Returns:
            a list of all Basis-Vectors
        """

        A, b, q, n, m = self.lwe.A, self.lwe.b, self.lwe.q, self.lwe.n, self.lwe.m

        # Kannan embedding
        B = np.concatenate((
            np.hstack((q*np.identity(m), np.zeros(shape=(m, n)), np.zeros(shape=(m, 1)))),
            np.hstack((A.T, -1*np.identity(m), np.zeros(shape=(n, 1)))),
            np.hstack((np.array([b]), np.zeros(shape=(1, m)), np.ones(shape=(1, 1))))
        ))

        # LLL - Algorithm
        return olll.reduction(B, 0.75)



    def findSecret(self, B):
        """
        Finds the secret amongst given Basis-Vectors and public Keys.

        Args:
            B: All Basis Vectors
            A: public key (Matrix) (length: nxm)
            b: public key (vector) (length: n)
        Returns:
            secret: the found secret | None
            error: the found error the vector b was manipulated by | None
        """

        A, b, q, n, m = self.lwe.A, self.lwe.b, self.lwe.q, self.lwe.n, self.lwe.m

        secret = None
        error = None
        
        for i in range(len(B)):
            #disect Basis-Vectors into (error, secret, 1)
            currentError = B[i][:n]
            currentSecret = B[i][n:n+m]

            #validate current Error-Secret Pair
            should_be_b = np.dot(A, currentSecret) % q

            if np.array_equal(b - currentError, should_be_b) or np.array_equal(b + currentError, should_be_b):
                secret = currentSecret
                error = currentError
                break    

        return secret, error


def testLWEAccuracy(n, m, q, length):
    """
    Test how accurate a random LWE is given n, m, q for a certain amount (length) of tests.

    Args:
        n: length of A, b, e
        m: length of secret
        q: mod q
        length: amount of tests run
    Returns:
        accuracy: Accuracy in %
    """
    
    cost = 2*(q//128)**m
    log_cost = math.log(cost,2)
    
    print(f"Enumeration/Brute-Force of the secret would cost a lot. Security level is: 2^{log_cost}")

    lwe = LWE(n, m, q)

    correct = 0

    for i in range(length):
        A, b, e, secret = lwe.generate()
        bit = random.randint(0, 1)
        u, v = lwe.encrypt(bit)
        
        _bit = lwe.decrypt(u, v, secret)
        correct += 1 if _bit == bit else 0

    return correct / length * 100



if __name__ == "__main__":

    n, m, q = 32, 64, 512

    #Teseting LWE Accuracy for parameters n, m, q
    print(f"Accuracy: {testLWEAccuracy(n, m, q, 100)}%")


    #Encrypting/Decrypting a String
    lwe = LWE(n, m, q)
    A, b, e, secret = lwe.generate()
    
    
    word = input("Type the word you want to encode: ")
    
    encrypted = lwe.encryptString(word)

    decoded_word = lwe.decryptString(encrypted, secret)
    
    print(f"Decrypted message: {decoded_word}")
