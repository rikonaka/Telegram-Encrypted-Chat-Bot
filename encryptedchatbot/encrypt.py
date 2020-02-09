#!/usr/bin/env python3

import nacl.secret
import nacl.utils
import nacl.encoding
import nacl.hash
from nacl.public import PrivateKey
from nacl.public import PublicKey
from nacl.public import Box
from nacl.exceptions import CryptoError

import emoji

from encryptedchatbot import config

def detect_encrypted_emoji_c(input_emoji):
    '''Use the C module.
    '''
    return emoji.detect(input_emoji)


def detect_encrypted_emoji(input_emoji):
    '''If the emoji is encrypted message.

    Retruns:
        1: is encrypted.
        0: not encrypted.
    '''

    first_emoji = input_emoji[0]
    # This value '😜'.
    test_label = '%s' % '\N{FACE WITH STUCK-OUT TONGUE AND WINKING EYE}'
    if first_emoji == test_label:
        return 1
    else:
        return 0


def convert_emoji_to_str_c(input_emoji):
    '''Use the C module.
    '''

    return emoji.decode(input_emoji)


def convert_emoji_to_str(input_emoji):
    '''Convert emoji to str
    '''

    output_str = str()
    for em in input_emoji:
        # Get last character.
        e = str(em.encode())[-3:-1]
        if e == '81' or e == '82' or e == '83' or e == '84' or e == '85' or e == '86':
            output_str = output_str + e[-1]
        elif e == '89':
            output_str = output_str + '7'
        elif e == '8a':
            output_str = output_str + '8'
        elif e == '8b':
            output_str = output_str + '9'
        elif e == '8c':
            output_str = output_str + 'a'
        elif e == '8d':
            output_str = output_str + 'b'
        elif e == '8f':
            output_str = output_str + 'c'
        elif e == '92':
            output_str = output_str + 'd'
        elif e == '93':
            output_str = output_str + 'e'
        elif e == '98':
            output_str = output_str + 'f'
        elif e == '9a':
            output_str = output_str + '0'

    return output_str


def convert_str_to_emoji_c(input_str):
    '''Use the C module.
    '''

    return emoji.encode(input_str)


def convert_str_to_emoji(input_str):
    '''Convert str to emoji
    '''

    # \xF0\x9F\x98\x9C
    output_emoji = '%s' % '\N{FACE WITH STUCK-OUT TONGUE AND WINKING EYE}'
    for ch in input_str:
        if ch == '0':
            output_emoji = output_emoji + \
                '%s' % '\N{KISSING FACE WITH CLOSED EYES}'
        elif ch == '1':
            output_emoji = output_emoji + \
                '%s' % '\N{GRINNING FACE WITH SMILING EYES}'
        elif ch == '2':
            output_emoji = output_emoji + \
                '%s' % '\N{FACE WITH TEARS OF JOY}'
        elif ch == '3':
            output_emoji = output_emoji + \
                '%s' % '\N{SMILING FACE WITH OPEN MOUTH}'
        elif ch == '4':
            output_emoji = output_emoji + \
                '%s' % '\N{SMILING FACE WITH OPEN MOUTH AND SMILING EYES}'
        elif ch == '5':
            output_emoji = output_emoji + \
                '%s' % '\N{SMILING FACE WITH OPEN MOUTH AND COLD SWEAT}'
        elif ch == '6':
            output_emoji = output_emoji + \
                '%s' % '\N{SMILING FACE WITH OPEN MOUTH AND TIGHTLY-CLOSED EYES}'
        elif ch == '7':
            output_emoji = output_emoji + \
                '%s' % '\N{WINKING FACE}'
        elif ch == '8':
            output_emoji = output_emoji + \
                '%s' % '\N{SMILING FACE WITH SMILING EYES}'
        elif ch == '9':
            output_emoji = output_emoji + \
                '%s' % '\N{FACE SAVOURING DELICIOUS FOOD}'
        elif ch == 'a':
            output_emoji = output_emoji + \
                '%s' % '\N{RELIEVED FACE}'
        elif ch == 'b':
            output_emoji = output_emoji + \
                '%s' % '\N{SMILING FACE WITH HEART-SHAPED EYES}'
        elif ch == 'c':
            output_emoji = output_emoji + \
                '%s' % '\N{SMIRKING FACE}'
        elif ch == 'd':
            output_emoji = output_emoji + \
                '%s' % '\N{UNAMUSED FACE}'
        elif ch == 'e':
            output_emoji = output_emoji + \
                '%s' % '\N{FACE WITH COLD SWEAT}'
        elif ch == 'd':
            output_emoji = output_emoji + \
                '%s' % '\N{PENSIVE FACE}'
        elif ch == 'e':
            output_emoji = output_emoji + \
                '%s' % '\N{CONFOUNDED FACE}'
        elif ch == 'f':
            output_emoji = output_emoji + \
                '%s' % '\N{FACE THROWING A KISS}'

    return output_emoji


def convert_bytes_to_str(input_bytes):
    '''Convert b'/x15' => '15'.

    Args:
        input_bytes: the bytes data.

    Return:
        output_hex: the hex string.
        For example: '15855552e017df932f358b90511372759f8b5c4a0b4432fb4549d127996e229d'
        len(output_hex) = 64.
    '''
    if not input_bytes:
        return

    input_bytearray = bytearray(input_bytes)
    output_hex = str()
    for b in input_bytearray:
        # b is decimal, but we want to show the hex in the text.
        # hex(21) = '0x15'(str).
        hex_str = hex(b).split('x')[1]
        if len(hex_str) < 2:
            hex_str = '0%s' % hex_str

        # private_key_text look like this:
        #
        #
        output_hex = '%s%s' % (output_hex, hex_str)

    return output_hex


def convert_str_to_bytes(input_hex):
    '''Convert  '15' => b'/x15'.

    Args:
        input_hex: the hex string.

    Return:
        output_bytes: the bytes data.
        For example: b'\x15\x85UR\xe0\x17\xdf\x93/5\x8b\x90Q\x13ru\x9f\x8b\\J\x0bD2\xfbEI\xd1\'\x99n"\x9d'
        len(output_bytes) = 32.
    '''
    # Combine each two character to form a hexadecimal number.
    if not input_hex:
        return

    cursor = 2
    b_list = list()
    length = len(input_hex)
    while cursor <= length:
        he = input_hex[cursor-2:cursor]
        # b_list's integers(range 0<=x<256)

        cursor += 2
        # Convert hex to decimal.
        if len(he) != 0:
            de = int(he, 16)
            b_list.append(de)

    output_bytes = bytearray(b_list)
    return bytes(output_bytes)


def blake2b_hash(plain_text):
    '''Generate a blake2b hash.
    Use the blake2b to generate a hash for user id, and use this hash to identified the user public_key

    Args:
        plain_text(str).

    Returns:
        Hash string.
        hash_text(str): generate result.
        None: error.

        result length is 64B.
    '''
    hasher = nacl.hash.blake2b
    try:
        plain_text = plain_text.encode()
        digest = hasher(plain_text, encoder=nacl.encoding.HexEncoder)
        hash_text = str(digest).split("'")[1]
    except Exception:
        return None

    return hash_text


def sha256_hash(plain_text):
    '''Generate a sha256 hash.
    Use the sha256 to generate a hash to identified the secret_key which used by symmetric encryption.

    Args:
        plain_text(str).

    Returns:
        Hash string.
        hash_text(str): generate result.
        None: error.

        result length is 64B.
    '''
    hasher = nacl.hash.sha256
    try:
        plain_text = plain_text.encode()
        digest = hasher(plain_text, encoder=nacl.encoding.HexEncoder)
        hash_text = str(digest).split("'")[1]
    except Exception:
        return None

    return hash_text


def symmetric_key_generate():
    '''Generate a secret key for user.

    Returns:
        A secret key.
        secret_key(bytes): generate result.
        None: error.
    '''
    try:
        secret_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    except CryptoError:
        return None

    return secret_key


def symmetric_encryption(secret_key, plain_text):
    '''Encrypt a message with the secret_key.

    Args:
        secret_key(bytes): generate from nacl.utils.random() which must be kept secret.
        plain_text(str): the text you want to encrypted.

    Returns:
        A dict result_dict.
        For example:
        {
            'cipher_text': ...(bytes),
            'nonce': ...(bytes)
        }
        None: error.
    '''
    if not secret_key or not plain_text:
        return

    if len(secret_key) != 32:
        return None

    byte_text = plain_text.encode()

    try:
        box = nacl.secret.SecretBox(secret_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(plaintext=byte_text, nonce=nonce)
    except CryptoError:
        # print(e.args)
        return None

    result_dict = dict()
    result_dict['cipher_text'] = encrypted.ciphertext
    result_dict['nonce'] = nonce

    return result_dict


def symmetric_decryption(secret_key, nonce, cipher_text):
    '''Decrypt a message with the secret_key.

    Args:
        secret_key(bytes): generate from nacl.utils.random() which must be kept secret.
        nonce: the nonce you used to encrypt.
        cipher_text(bytes): the text you want to decrypted.

    Returns:
        A str plain_text.
        plain_text(str): decryption result.
        None: error.
    '''
    if not secret_key or not nonce or not cipher_text:
        return None

    try:
        box = nacl.secret.SecretBox(secret_key)
        plain_text = box.decrypt(ciphertext=cipher_text, nonce=nonce)
    except CryptoError:
        # print(e)
        return None

    plain_text = plain_text.decode('utf-8')
    return plain_text


def asymmetric_key_generate():
    '''Generate the private key and public key for user.

    Returns:
        A dict composed of rivate key and public key.
        For example:
        {
            'private_key': ...(bytes),
            'public_key': ...(bytes)
        }
        len(private_key) = len(public_key) = 32.
        None: error.
    '''
    result_dict = dict()

    try:
        gen = PrivateKey.generate()
    except CryptoError:
        return None

    result_dict['private_key'] = gen._private_key
    result_dict['public_key'] = gen.public_key._public_key

    return result_dict


def asymmetric_encryption(ours_private_key, target_public_key, plain_text):
    '''Encrypt a message with the ours private_key and the public_key used by the target.

    Args:
        ours_private_key(bytes): generate from asmmetric_key_generate.
        target_public_key(bytes): generate from asmmetric_key_generate, but user query from the server, user don't have this key.
        plain_text(str): the text you want to encrypted.

    Returns:
        A dict result_dict.
        For example:
        {
            'cipher_text': ...(bytes),
            'nonce': ...(bytes)
        }
        None: error.
    '''

    bytes_text = plain_text.encode()
    private_key_object = PrivateKey(ours_private_key)
    public_key_object = PublicKey(target_public_key)
    try:
        encrypt_box = Box(private_key_object, public_key_object)
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        encrypted = encrypt_box.encrypt(bytes_text, nonce=nonce)
    except Exception:
        # print(e.args)
        return None

    result_dict = dict()
    result_dict['cipher_text'] = encrypted.ciphertext
    result_dict['nonce'] = nonce
    return result_dict


def asymmetric_decryption(ours_private_key, target_public_key, nonce, cipher_text):
    '''Decrypt a message with our pirvate_key and the public used by target.

    Args:
        ours_private_key(bytes).
        target_public_key(bytes).
        nonce: the nonce you used to encrypt.
        cipher_text(bytes): the text you want to decrypted.

    Returns:
        A str plain_text.
        plain_text(str): decryption result.
        None: error.
    '''

    private_key_object = PrivateKey(ours_private_key)
    public_key_object = PublicKey(target_public_key)

    try:
        decrypt_box = Box(private_key_object, public_key_object)
        plain_text = decrypt_box.decrypt(ciphertext=cipher_text, nonce=nonce)
    except Exception:
        return None

    plain_text = plain_text.decode('utf-8')
    return plain_text


def main():
    '''For encrypt.py test'''

    # uid = 711223411
    # print(len(blake2b_hash(str(uid))))

    nonce_str = '5e3d0421c1f27c19bb02b293ff7ef2522329629bf1494691d619770e956c2aa8'
    print(convert_str_to_bytes(nonce_str))

    # Symmetric test success.
    # secret_key = symmetric_key_generate()
    # encryp_dict = symmetric_encryption(
    #     secret_key, 'Hello, this is the test message')

    # cipher_text = encryp_dict['cipher_text']
    # cipher_text_str = convert_bytes_to_str(cipher_text)
    # nonce = encryp_dict['nonce']
    # print(secret_key)
    # print(len(secret_key))
    # print(cipher_text)
    # print(len(cipher_text))
    # print(nonce)
    # print(len(nonce))
    # print('\n')

    # nonce_str = convert_bytes_to_str(nonce)
    # secret_key_str = convert_bytes_to_str(secret_key)
    # print(secret_key_str)
    # print(len(secret_key_str))
    # print(cipher_text_str)
    # print(len(cipher_text_str))
    # print(nonce_str)
    # print(len(nonce_str))
    # print('\n')

    # nonce_bytes = convert_str_to_bytes(nonce_str)
    # cipher_bytes = convert_str_to_bytes(cipher_text_str)
    # secret_key_bytes = convert_str_to_bytes(secret_key_str)
    # print(secret_key_bytes)
    # print(len(secret_key_bytes))
    # print(cipher_bytes)
    # print(len(cipher_bytes))
    # print(nonce_bytes)
    # print(len(nonce_bytes))
    # plain_text = symmetric_decryption(
    #     secret_key_bytes, nonce_bytes, cipher_bytes)
    # print(plain_text)

    # Asymmetric test success.
    # ours_key_dict = asymmetric_key_generate()
    # ours_private_key_bytes = ours_key_dict['private_key']
    # ours_public_key_bytes = ours_key_dict['public_key']
    # print('1')
    # print(ours_private_key_bytes)
    # print(ours_public_key_bytes)
    # print('\n')

    # ours_private_key_str = convert_bytes_to_str(ours_private_key_bytes)
    # ours_public_key_str = convert_bytes_to_str(ours_public_key_bytes)
    # print('2')
    # print(ours_private_key_str)
    # print(ours_public_key_str)
    # print('\n')

    # target_key_dict = asymmetric_key_generate()
    # target_private_key_bytes = target_key_dict['private_key']
    # target_public_key_bytes = target_key_dict['public_key']
    # print('3')
    # print(target_private_key_bytes)
    # print(target_public_key_bytes)
    # print('\n')

    # target_private_key_str = convert_bytes_to_str(target_private_key_bytes)
    # target_public_key_str = convert_bytes_to_str(target_public_key_bytes)
    # print('4')
    # print(target_private_key_str)
    # print(target_public_key_str)
    # print('\n')

    # ours_private_key_convert_bytes = convert_str_to_bytes(ours_private_key_str)
    # target_public_key_convert_bytes = convert_str_to_bytes(
    #     target_public_key_str)
    # print('5')
    # print(ours_private_key_convert_bytes)
    # print(target_public_key_convert_bytes)
    # print('\n')

    # encrypted_result = asymmetric_encryption(ours_private_key_convert_bytes,
    #                                          target_public_key_convert_bytes, 'Test Test Test')

    # cipher_text_bytes = encrypted_result['cipher_text']
    # nonce_bytes = encrypted_result['nonce']
    # print('6')
    # print(cipher_text_bytes)
    # print(nonce_bytes)
    # print('\n')

    # cipher_text_str = convert_bytes_to_str(cipher_text_bytes)
    # nonce_str = convert_bytes_to_str(nonce_bytes)
    # print('7')
    # print(cipher_text_str)
    # print(nonce_str)
    # print('\n')

    # cipher_text_convert_bytes = convert_str_to_bytes(cipher_text_str)
    # nonce_convert_bytes = convert_str_to_bytes(nonce_str)

    # plain_text = asymmetric_decryption(
    #     ours_private_key_convert_bytes, target_public_key_convert_bytes, nonce_convert_bytes, cipher_text_convert_bytes)
    # print(plain_text)


if __name__ == "__main__":
    main()
