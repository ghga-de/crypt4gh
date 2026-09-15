"""Crypto primitives for Crypt4GH, on top of the cryptography package and hashlib.

This module replaces the former libsodium bindings. It keeps their name and
functions, so callers don't change, and it returns the same bytes as libsodium.
"""

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import CIPHER_DIFF

NONCE_LEN = 12
KEY_LEN = 32

##############################################################
##
##    ChaCha20-Poly1305 (IETF), as nonce || ciphertext || MAC
##
##############################################################

def chacha20poly1305_encrypt(ciphersegment, segment, key):
    '''Encrypt `segment` into `ciphersegment`, with a random nonce.

    Returns the number of bytes written to `ciphersegment`.'''
    clen = len(segment) + CIPHER_DIFF
    if len(ciphersegment) < clen:
        raise AssertionError('Invalid buffer sizes')
    nonce = os.urandom(NONCE_LEN)
    out = memoryview(ciphersegment)
    out[:NONCE_LEN] = nonce
    ChaCha20Poly1305(key).encrypt_into(nonce, segment, None, out[NONCE_LEN:clen])
    return clen

def chacha20poly1305_decrypt(segment, ciphersegment, key):
    '''Decrypt `ciphersegment` into `segment`.

    Returns the number of bytes written to `segment`.'''
    clen = len(ciphersegment)
    if clen <= CIPHER_DIFF or len(segment) < clen - CIPHER_DIFF:
        raise AssertionError('Invalid buffer sizes')
    data = memoryview(ciphersegment)
    try:
        ChaCha20Poly1305(key).decrypt_into(data[:NONCE_LEN], data[NONCE_LEN:], None,
                                           memoryview(segment)[:clen - CIPHER_DIFF])
    except InvalidTag:
        raise ValueError('Ciphersegment decryption failed') from None
    return clen - CIPHER_DIFF

##############################################################
##
##    X25519 key exchange, as libsodium's crypto_kx
##
##############################################################

def derive_pk(sk):
    '''Return the X25519 public key of the secret key `sk`.'''
    if len(sk) != KEY_LEN:
        raise AssertionError('wrong input size')
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()

def _session_key(sk, peer_pk, client_pk, server_pk):
    # crypto_kx hashes X25519(sk, peer_pk) || client_pk || server_pk with BLAKE2b-512.
    # The first half is the key from the server to the client, the one Crypt4GH uses.
    # BLAKE2b's digest size is one of its parameters, so a 32-byte digest would differ.
    if not len(sk) == len(client_pk) == len(server_pk) == KEY_LEN:
        raise AssertionError('Wrong key sizes')
    q = X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(peer_pk))
    h = hashlib.blake2b(digest_size=64)
    h.update(q)
    h.update(client_pk)
    h.update(server_pk)
    return h.digest()[:KEY_LEN]

def kx_server(server_pk, server_sk, client_pk):
    '''Return the session key that the server shares with the client `client_pk`.'''
    return _session_key(server_sk, client_pk, client_pk, server_pk)

def kx_client(client_pk, client_sk, server_pk):
    '''Return the session key that the client shares with the server `server_pk`.'''
    return _session_key(client_sk, server_pk, client_pk, server_pk)

##############################################################
##
##    Ed25519 keys (from OpenSSH) to X25519 keys
##
##############################################################

# Curve25519 constants (RFC 7748, RFC 8032)
_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_L = 2**252 + 27742317777372353535851937790883648493
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

def _point_add(a, b):
    # Edwards addition in extended coordinates (RFC 8032, section 5.1.4)
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)

def _in_main_subgroup(x, y):
    # [L]A is the neutral element (0, 1) exactly when A lies in the subgroup of prime order L
    q = (0, 1, 1, 0)
    a = (x, y, 1, x * y % _P)
    n = _L
    while n:
        if n & 1:
            q = _point_add(q, a)
        a = _point_add(a, a)
        n >>= 1
    return q[0] == 0 and q[1] == q[2]

def sign_ed25519_pk_to_curve25519(ed25519_pk):
    '''Convert an Ed25519 public key to an X25519 public key.

    Like libsodium, it rejects points that are not on the curve,
    that have a small order, or that lie outside the prime-order subgroup.'''
    if len(ed25519_pk) != 32:
        raise ValueError('Invalid ed25519 public key size')
    # Like libsodium, accept non-canonical encodings of y.
    # The sign of x changes neither the subgroup test nor u, so it is ignored.
    y = (int.from_bytes(ed25519_pk, 'little') & ((1 << 255) - 1)) % _P
    # Recover x from y (RFC 8032, section 5.1.3)
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    # y == 1 is the neutral element, the only small-order point of the subgroup
    if (x * x - x2) % _P or y == 1 or not _in_main_subgroup(x, y):
        raise RuntimeError("Can't convert ed25519 public key to curve25519.")
    # Edwards to Montgomery: u = (1 + y) / (1 - y)
    u = (1 + y) * pow(1 - y, _P - 2, _P) % _P
    return u.to_bytes(32, 'little')

def sign_ed25519_sk_to_curve25519(ed25519_skpk):
    '''Convert an Ed25519 secret key (seed || public key) to an X25519 secret key.'''
    if len(ed25519_skpk) != 64:
        raise ValueError('Invalid ed25519 secret key size')
    h = bytearray(hashlib.sha512(ed25519_skpk[:32]).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)
