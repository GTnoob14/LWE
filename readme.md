# LWE

### 1) Encryption

Learning with Errors is a quantum-robust method of cryptography.
First, we generate a secret vector s (length n), a public matrix A (size m x n), and a secret error vector e (size m).
Note: q-1 is the maximum number to be used in A, s, b, and e (every number will be taken modulo q)

Then, we calculate the public vector B = A * s + e.

By only knowing B and A (which are public), one can't (or only very hard) calculate the secret vectors s and e.

Assuming that A constructs a linear system of equations with s being the set of solutions for A, one can construct one linear equation by randomly taking rows of A and adding them into a new vector v and doing the same with b, which will result in a number u. By adding new errors e1 and e2 to u and v respectfully one can obfuscate the outcome even more.
Note: u*s ≈ v

Now one can hide a bit (1 or 0) in u and v by adding q/2 to v when the bit is 1 and adding 0 when the bit is 0.

The exact process on how to encrypt a single bit is found here: https://www.cybersecurity.blog.aisec.fraunhofer.de/en/a-somewhat-gentle-introduction-to-lattice-based-post-quantum-cryptography/#LWEfundamentals

### 2) Decryption

The decryption can only be done with knowledge of s.

One receives the vector v and the number u and can decrypt the encrypted bit by looking at whether u*s ≈ v or not.

### 3) Accuracy

Depending on your choice of the parameters n, m, q and the error/secret distribution Z the LWE encryption/decryption method can produce results of varying accuracy.

### 4) Strings

Strings can be represented by a list of characters where each character is stored a 8 bits which in return can be encrypted as <u, v> pairs.

### 5) Cracking

The encryption method LWE can be cracked very easily for small parameters (eg: n=8, m=8, q=256, Z={-2, -1, 0, 1, 2}) by converting the process into a Closest/Shortest Vector Problem and solving that by using an algorithm like LLL.
