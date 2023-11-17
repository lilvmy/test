from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_ec_key():
    # the data owner's private key sk_DO
    sk_DO = []
    k_d = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_DO.append(k_d)
    alpha = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_DO.append(alpha)
    kesi = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_DO.append(kesi)
    fai = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_DO.append(fai)

    # the data owner's public key pk_DO
    pk_DO = []
    g_k_d = k_d.public_key()
    pk_DO.append(g_k_d)
    g_alpha = k_d.public_key()
    pk_DO.append(g_alpha)
    g_kesi = k_d.public_key()
    pk_DO.append(g_kesi)
    g_fai = k_d.public_key()
    pk_DO.append(g_fai)

    # the user's private key sk_U
    sk_U= []
    gamma = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_U.append(gamma)
    delta = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_U.append(delta)
    beta = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_U.append(beta)
    miu = ec.generate_private_key(ec.SECP256R1(), default_backend())
    sk_U.append(miu)

    # the user's public key pk_U
    pk_U = []
    g_gamma = gamma.public_key()
    pk_U.append(g_gamma)
    g_delta = delta.public_key()
    pk_U.append(g_delta)
    g_beta = beta.public_key()
    pk_U.append(g_beta)
    g_miu = miu.public_key()
    pk_U.append(g_miu)

    return sk_DO, pk_DO, sk_U, pk_U
def derive_shared_key(sk_DO, pk_DO, sk_U, pk_U):
    # share document and cnt_W encryption key
    shared_docCntW_key = sk_DO[0].exchange(ec.ECDH(), pk_U[0])

    # share keyword w encryption key
    shared_w_key = sk_DO[2].exchange(ec.ECDH(), pk_U[2])

    #shared xtrap encryption key
    share_xtrap_key = sk_DO[1].exchange(ec.ECDH(),pk_U[1])

    #shared role encryption key
    shared_role_key = sk_DO[3].exchange(ec.ECDH(),pk_U[3])
    return shared_docCntW_key, shared_w_key, share_xtrap_key, shared_role_key



if __name__ == "__main__":
    ss = generate_ec_key()
    aa = derive_shared_key(ss[0], ss[1], ss[2], ss[3])
    print(aa)
