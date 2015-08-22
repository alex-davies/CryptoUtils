# Crypto Utils

A storage for some common cryptography wrapping classes that can be easily copied into future projects

# Encryptor

Encrypts and decrypts data easily. 

```C#
var encryptor = new Encryptor("my super secret key");

var encryptedText = encryptor.Encrypt("data which i dont want to store in plain text");
var decryptedText = encryptor.Decrypt(encryptedText);

```

# Hasher

Hash data (like a password) easily. The salt is generated and encoded along with the hash

```C#
var hash = hasher.Hash("pass@word");

bool isPasswordCorrect = hasher.CheckHash("pass@word", hash)

```