# Hybrid Post-quantum Secure Messaging Project

this is just a python project that combines rsa encryption (classical) and crystals-kyber (post-quantum) to create a hybrid encrypted messaging system. i built this pretty much just to learn about post quantum cryptography and how it compares to the encryption we use today.

---

## what is this and why does it matter

right now most encryption on the internet uses rsa, which works because it's really hard for regular computers to factor giant numbers. The problem is that quantum computers running something called shor's algorithm could break rsa pretty easily once they're powerful enough.

crystals-kyber is one of the algorithms nist picked in 2022 to replace rsa. it's based on a math problem called "learning with errors" which even quantum computers are expected to struggle with.

since we're in a transition period where quantum computers aren't powerful enough yet to break rsa but we need to start preparing now, experts recommend using both at the same time. that's called hybrid encryption, and that's what this project basically does.

---

## what the project does

- generates rsa-2048 keys and crystals-kyber512 keys
- encrypts a message using both algorithms together
- decrypts it and verifies everything came through correctly
- simulates two users (alice and bob ) sending a secure message
- benchmarks rsa vs kyber and shows the performance difference

---

## how to run it

first make sure you have python installed, then set up the environment:

```
python -m venv venv
venv\Scripts\activate.bat
pip install -r requirements.txt
```

then run the project:

```
python hybrid_secure_messaging.py
```

you'll get a menu that lets you run the simulation, the benchmark, or both

---

## example output

```
hybrid post-quantum secure messaging system
-------------------------------------------
1. run message simulation
2. run benchmarks
3. run both

pick an option (1/2/3): 3
enter a message: hello from the post-quantum era!

=======================================================
   hybrid post-quantum secure messaging demo
=======================================================

[setup] generating keys for alice...
  rsa-2048 keys created
  kyber512 keys created

[bob] wants to send: 'hello from the post-quantum era!'
[bob] encrypting with rsa + kyber...
  message encrypted in 2.34 ms
  rsa ciphertext size: 256 bytes
  kyber ciphertext size: 768 bytes
  aes ciphertext size: 32 bytes

[alice] received encrypted message
[alice] decrypting...
  message decrypted in 15.12 ms

[results]
  original:  hello from the post-quantum era!
  decrypted: hello from the post-quantum era!
  kyber secret verified: yes
  message integrity ok:  yes

  hybrid encryption worked!
```

---

## benchmark results (rsa vs kyber)
kyber is significantly faster than rsa for key generation and decryption. the tradeoff is slightly larger key and ciphertext sizes, but that's considered acceptable for the security benefits.

---

## files

```
pqc_secure_messaging/
hybrid_secure_messaging.py   # main script
requirements.txt             # dependencies
 README.md                    # (this file)
```

---

## dependencies

- pycryptodome - for rsa and aes encryption
- pqcrypto - for crystals-kyber post-quantum encryption

---

## my references

- nist post-quantum cryptography project: https://csrc.nist.gov/projects/post-quantum-cryptography
- crystals-kyber spec (fips 203): https://csrc.nist.gov/pubs/fips/203/final
- shor's algorithm explanation: https://en.wikipedia.org/wiki/Shor%27s_algorithm

---


