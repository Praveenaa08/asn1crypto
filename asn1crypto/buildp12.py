import sys
import getpass
import os
import hashlib
import hmac
from asn1crypto import core, pkcs12, x509, pem, algos, keys, cms

# --- Custom Encryption and ASN.1 Wrapping ---

def build_encrypted_private_key_info(ciphertext, salt, iterations, iv):
    """
    Wraps the encrypted key bytes into an ASN.1 EncryptedPrivateKeyInfo
    """
    return keys.EncryptedPrivateKeyInfo({
        'encryption_algorithm': algos.EncryptionAlgorithm({
            'algorithm': 'pbes2',
            'parameters': algos.Pbes2Params({
                'key_derivation_func': algos.KdfAlgorithm({
                    'algorithm': 'pbkdf2',
                    'parameters': algos.Pbkdf2Params({
                        'salt': core.OctetString(salt),
                        'iteration_count': iterations,
                        'prf': algos.HmacAlgorithm({'algorithm': '1.2.840.113549.2.9'})  # OID for hmacWithSHA256
                    })
                }),
                'encryption_scheme': algos.EncryptionAlgorithm({
                    'algorithm': 'aes256_cbc',
                    'parameters': core.OctetString(iv)
                })
            })
        }),
        'encrypted_data': core.OctetString(ciphertext)
    })

def build_safe_bag_key(encrypted_info):
    """
    Create a SafeBag holding the ASN.1-wrapped encrypted private key
    """
    safe_bag = pkcs12.SafeBag({
        'bag_id': '1.2.840.113549.1.12.10.1.2',
        'bag_value': encrypted_info,
        'bag_attributes': []
    })
    return safe_bag

def build_safe_bag_cert(cert):
    """
    Create a SafeBag holding an X.509 certificate
    """
    cert_bag = pkcs12.CertBag({
        'cert_id': '1.2.840.113549.1.9.22.1',
        'cert_value': cert
    })
    safe_bag = pkcs12.SafeBag({
        'bag_id': '1.2.840.113549.1.12.10.1.3',
        'bag_value': cert_bag,
        'bag_attributes': []
    })
    return safe_bag

def build_mac_data(auth_safe_bytes, password, salt, iterations=2048, digest_algorithm='sha256'):
    # Encode password as UTF-16BE with null terminator
    pw_bytes = b"" if password == "" else (password + '\0').encode('utf-16be')

    dklen = hashlib.new(digest_algorithm).digest_size
    mac_key = hashlib.pbkdf2_hmac(digest_algorithm, pw_bytes, salt, iterations, dklen=dklen)
    mac = hmac.new(mac_key, auth_safe_bytes, digest_algorithm).digest()

    digest_info = algos.DigestInfo({
        'digest_algorithm': algos.DigestAlgorithm({
            'algorithm': 'sha256',
            'parameters': core.Null()
        }),
        'digest': mac
    })

    return pkcs12.MacData({
        'mac': digest_info,
        'mac_salt': salt,
        'iterations': iterations
    })


def build_pfx_with_mac(encrypted_info, certs, password, salt, iterations=2048):
    key_safe_bags = [build_safe_bag_key(encrypted_info)]
    cert_safe_bags = [build_safe_bag_cert(cert) for cert in certs]

    key_content_info = pkcs12.ContentInfo({
        'content_type': 'data',
        'content': core.OctetString(pkcs12.SafeContents(key_safe_bags).dump())
    })

    cert_content_info = pkcs12.ContentInfo({
        'content_type': 'data',
        'content': core.OctetString(pkcs12.SafeContents(cert_safe_bags).dump())
    })

    authenticated_safe = pkcs12.AuthenticatedSafe([key_content_info, cert_content_info])
    encoded_auth_safe = authenticated_safe.dump()

    outer_content_info = cms.ContentInfo({
        'content_type': 'data',
        'content': core.OctetString(encoded_auth_safe)
    })

    # Generate a fresh MAC salt (8 bytes)
    mac_salt = os.urandom(8)
    print(f"Using MAC salt: {mac_salt.hex()}")

    pfx = pkcs12.Pfx({
        'version': 3,
        'auth_safe': outer_content_info,
        'mac_data': build_mac_data(encoded_auth_safe, password, mac_salt, iterations)
    })

    return pfx.dump()



def load_pem_certs(pem_file):
    """
    Load all certificates from a PEM file
    """
    certs = []
    with open(pem_file, 'rb') as f:
        data = f.read()
    while data:
        if not pem.detect(data):
            break
        _, _, der_bytes = pem.unarmor(data)
        cert = x509.Certificate.load(der_bytes)
        certs.append(cert)
        data = data[data.find(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----"):]
    return certs

def load_encrypted_key(ciphertext_file):
    """
    Load raw encrypted private key bytes
    """
    with open(ciphertext_file, 'rb') as f:
        return f.read()

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} encrypted_key.bin cert_chain.pem")
        sys.exit(1)

    # --- Input files
    encrypted_key_file = sys.argv[1]
    cert_chain_file = sys.argv[2]

    # --- Fixed encryption parameters (MUST match encryption script)
    salt = bytes.fromhex("D7991A3F8E8788188192A375D421E364")
    iterations = 2048
    iv = bytes.fromhex("586089D1C92BA044137B11B879A1781D")

    # --- Load inputs
    encrypted_key_bytes = load_encrypted_key(encrypted_key_file)
    certs = load_pem_certs(cert_chain_file)

    password = getpass.getpass("Enter password to encrypt the .p12 (used for MAC): ")

    # --- Wrap encrypted key in ASN.1
    encrypted_info = build_encrypted_private_key_info(
        encrypted_key_bytes, salt, iterations, iv
    )

    # --- Build and write PFX
    pfx_data = build_pfx_with_mac(encrypted_info, certs, password, salt, iterations)

    with open("outputFinal.p12", "wb") as f:
        f.write(pfx_data)

    print("✅ PKCS#12 file 'outputFinal.p12' created successfully.")

if __name__ == "__main__":
    main()
