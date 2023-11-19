from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import keyGen

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(16))
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, cipher.iv

def aes_decrypt(key, ciphertext, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


# if __name__ == "__main__":
#
#     # Example usage
#     message = b"Hello, AES encryption using ECDH with Type A elliptic curve."
#
#     sk_DO,pk_DO,sk_U,pk_U = keyGen.generate_ec_key();
#     shared_docCntW_key, shared_w_key, share_xtrap_key, shared_role_key = keyGen.derive_shared_key(sk_DO,pk_DO,sk_U,pk_U)
#
#
#     # Encrypt with Alice's key and decrypt with Bob's key
#     ciphertext_alice, iv_alice = aes_encrypt(shared_docCntW_key, message)
#     plaintext_bob = aes_decrypt(shared_docCntW_key, ciphertext_alice, iv_alice)
#
#     print(f"Decrypted by Bob: {plaintext_bob.decode('utf-8')}")
