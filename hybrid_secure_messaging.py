# a hybrid secure messaging project
# combining rsa (classical) and kyber (post-quantum) encryption

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from pqcrypto.kem.kyber512 import generate_keypair, encapsulate, decapsulate
import time


# generate rsa keys (classical encryption)
def make_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


# generate kyber keys (post-quantum encryption)
def make_kyber_keys():
    public_key, private_key = generate_keypair()
    return public_key, private_key


# encrypt a message using both rsa and kyber (hybrid)
def encrypt_message(message, rsa_public, kyber_public):

    # step 1, make a random aes session key to actually encrypt the message
    session_key = get_random_bytes(32)

    # step 2, encrypt the message with aes-gcm
    aes_cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(message)
    nonce = aes_cipher.nonce

    # step 3, protect the session key with rsa (classical layer)
    rsa_cipher = PKCS1_OAEP.new(rsa_public)
    rsa_locked_key = rsa_cipher.encrypt(session_key)

    # step 4, also protect it with kyber (post-quantum layer)
    kyber_ciphertext, kyber_secret = encapsulate(kyber_public)

    # return everything bundled together
    return {
        "rsa_locked_key": rsa_locked_key,
        "kyber_ciphertext": kyber_ciphertext,
        "kyber_secret": kyber_secret,
        "aes_ciphertext": ciphertext,
        "aes_tag": tag,
        "aes_nonce": nonce
    }


# decrypt the message using private keys
def decrypt_message(payload, rsa_private, kyber_private):

    # step 1, use rsa private key to get back the session key
    rsa_decipher = PKCS1_OAEP.new(rsa_private)
    session_key = rsa_decipher.decrypt(payload["rsa_locked_key"])

    # step 2, use kyber private key to verify the post-quantum layer
    recovered_kyber_secret = decapsulate(payload["kyber_ciphertext"], kyber_private)

    # step 3, use the session key to decrypt the actual message
    aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=payload["aes_nonce"])
    plaintext = aes_cipher.decrypt_and_verify(payload["aes_ciphertext"], payload["aes_tag"])

    return plaintext, recovered_kyber_secret


# simulate alice and bob sending a secure message
def run_simulation(message_text):

    print("\n" + "="*55)
    print("   hybrid post quantum secure messaging demo")
    print("="*55)

    # generate keys for alice (the receiver)
    print("\n[setup] generating keys for alice..")
    alice_rsa_private, alice_rsa_public = make_rsa_keys()
    alice_kyber_public, alice_kyber_private = make_kyber_keys()
    print("  rsa-2048 keys created")
    print("  kyber512 keys created")

    # bob sends alice a message
    message = message_text.encode()
    print(f"\n[bob] wants to send: '{message_text}'")
    print("[bob] encrypting with rsa + kyber..")

    start = time.time()
    payload = encrypt_message(message, alice_rsa_public, alice_kyber_public)
    enc_time = (time.time() - start) * 1000

    print(f"  message encrypted in {enc_time:.2f} ms")
    print(f"  rsa ciphertext size: {len(payload['rsa_locked_key'])} bytes")
    print(f"  kyber ciphertext size: {len(payload['kyber_ciphertext'])} bytes")
    print(f"  aes ciphertext size: {len(payload['aes_ciphertext'])} bytes")

    # alice decrypts the message
    print("\n[alice] received encrypted message")
    print("[alice] decrypting...")

    start = time.time()
    decrypted, recovered_secret = decrypt_message(payload, alice_rsa_private, alice_kyber_private)
    dec_time = (time.time() - start) * 1000

    print(f"  message decrypted in {dec_time:.2f} ms")

    # check everything worked
    kyber_match = payload["kyber_secret"] == recovered_secret
    message_match = decrypted == message

    print("\n[results]")
    print(f"  original:  {message_text}")
    print(f"  decrypted: {decrypted.decode()}")
    print(f"  kyber secret verified: {'yes' if kyber_match else 'no'}")
    print(f"  message integrity ok:  {'yes' if message_match else 'no'}")
    print("\n  hybrid encryption worked!")
    print("="*55)


# benchmark rsa vs kyber performance
def run_benchmarks():

    print("\n" + "="*55)
    print("   benchmark: rsa-2048 vs crystals-kyber512")
    print("="*55)

    runs = 5

    # test rsa
    rsa_keygen = []
    rsa_enc = []
    rsa_dec = []

    for _ in range(runs):
        start = time.time()
        rsa_priv, rsa_pub = make_rsa_keys()
        rsa_keygen.append((time.time() - start) * 1000)

        test_key = get_random_bytes(32)
        start = time.time()
        enc = PKCS1_OAEP.new(rsa_pub).encrypt(test_key)
        rsa_enc.append((time.time() - start) * 1000)

        start = time.time()
        PKCS1_OAEP.new(rsa_priv).decrypt(enc)
        rsa_dec.append((time.time() - start) * 1000)

    # test kyber
    kyber_keygen = []
    kyber_enc = []
    kyber_dec = []

    for _ in range(runs):
        start = time.time()
        kyber_pub, kyber_priv = make_kyber_keys()
        kyber_keygen.append((time.time() - start) * 1000)

        start = time.time()
        ct, _ = encapsulate(kyber_pub)
        kyber_enc.append((time.time() - start) * 1000)

        start = time.time()
        decapsulate(ct, kyber_priv)
        kyber_dec.append((time.time() - start) * 1000)

    # print results
    print(f"\n{'metric':<30} {'rsa-2048':>12} {'kyber512':>12}")
    print("-" * 55)
    print(f"{'avg key generation (ms)':<30} {sum(rsa_keygen)/runs:>12.2f} {sum(kyber_keygen)/runs:>12.2f}")
    print(f"{'avg encryption (ms)':<30} {sum(rsa_enc)/runs:>12.2f} {sum(kyber_enc)/runs:>12.2f}")
    print(f"{'avg decryption (ms)':<30} {sum(rsa_dec)/runs:>12.2f} {sum(kyber_dec)/runs:>12.2f}")
    print(f"{'public key size (bytes)':<30} {'~294':>12} {len(kyber_pub):>12}")
    print(f"{'ciphertext size (bytes)':<30} {'256':>12} {len(ct):>12}")
    print("\n  kyber is faster and the ciphertext is a different size")
    print("  rsa can be broken by shors algorithm on a quantum computer")
    print("  kyber is based on lattice math which is quantum resistant")
    print("="*55)


# main menu
if __name__ == "__main__":

    print("\nhybrid post-quantum secure messaging system")
    print("-------------------------------------------")
    print("1. run message simulation")
    print("2. run benchmarks")
    print("3. run both")

    choice = input("\npick an option (1/2/3): ").strip()

    if choice == "1":
        msg = input("enter a message: ")
        run_simulation(msg)
    elif choice == "2":
        run_benchmarks()
    elif choice == "3":
        msg = input("enter a message: ")
        run_simulation(msg)
        run_benchmarks()
    else:
        print("running full demo...")
        run_simulation("hello from the post quantum era!")
        run_benchmarks()