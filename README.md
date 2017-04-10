# crypto

A small crypto package containing some useful utility functions

## func GenKeyPair

```
func GenKeyPair() ([32]byte, [32]byte, error)
```

Generates a private and public key pair generated with the [Curve25519](http://cr.yp.to/ecdh.html) Diffe-Hellman function. Returns (privateKey, publicKey, error).

## func GenSharedSecret

```
func GenSharedSecret(selfPri, otherPub [32]byte) [32]byte
```

Generates a shared secret with the client's private key and a peers public key using the [Curve25519] Diffie-Hellman function.

# func Hash

```
func Hash(tag string, data []byte) []byte
```

Generates an authenticated 256 bit hash with the SHA-2 SHA-512/256 hash function in combination with HMAC.

# func Encrypt

```
func Encrypt(plaintext []byte, secret [32]byte) ([]byte, error)
```

Returns an encrypted version of the provided plaintext using AES.

# func Decrypt

```
func Decrypt(ciphertext []byte, secret [32]byte) ([]byte, error)
```

Returns a decrypted version of the provided ciphertext using AES.

## References

- [Curve25519](http://cr.yp.to/ecdh.html)
- [Diffie-Hellman Key Exchange - A Non-Mathematician’s Explanation](https://docs.google.com/viewer?a=v&pid=sites&srcid=bmV0aXAuY29tfGhvbWV8Z3g6NTA2NTM0YmNhZjRhZDYzZQ)
- George Tankersley - Crypto for Go Developers
  - [video](https://www.youtube.com/watch?v=2r_KMzXB74w)
  - [slides](https://speakerdeck.com/gtank/crypto-for-go-developers)
  - [code](https://github.com/gtank/cryptopasta)
