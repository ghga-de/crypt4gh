import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_ssh_private_key, load_ssh_public_key

from .. import crypto
from ..exceptions import exit_on_invalid_passphrase

LOG = logging.getLogger(__name__)

MAGIC_WORD = b'openssh-key-v1\x00'


@exit_on_invalid_passphrase
def parse_private_key(data, callback):
    '''Parse an OpenSSH ed25519 private key, given in PEM format.

    The callback is only asked for the passphrase if the key is encrypted.
    Returns the X25519 secret key and public key.'''

    try:
        key = load_ssh_private_key(data, password=None)
    except TypeError: # the key is encrypted
        assert( callback and callable(callback) )
        passphrase = callback().encode()
        if not passphrase:
            raise ValueError("Passphrase required")
        key = load_ssh_private_key(data, password=passphrase)

    if not isinstance(key, Ed25519PrivateKey):
        raise NotImplementedError('Unsupported SSH key type: only ed25519 is supported')

    sk = key.private_bytes_raw()
    pk = key.public_key().public_bytes_raw()
    return (crypto.sign_ed25519_sk_to_curve25519(sk + pk),
            crypto.sign_ed25519_pk_to_curve25519(pk))


def get_public_key(line):
    key = load_ssh_public_key(line)
    if not isinstance(key, Ed25519PublicKey):
        raise NotImplementedError(f'Unsupported SSH key format: {line[0:11]}')
    return crypto.sign_ed25519_pk_to_curve25519(key.public_bytes_raw())
