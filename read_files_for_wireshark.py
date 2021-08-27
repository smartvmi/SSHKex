#!/usr/bin/env python3
import binascii
import sys

from Cryptodome.Cipher import AES
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Hash import Poly1305

from cipher_enum import Cipher_Enum

iv_a = iv_b = key_c = key_d = ''
save_iv_a = save_iv_b = ''
iv_a_add = iv_b_add = 0
result_array = []
number = 0
data = None
enc_name = ''
iv_a_checked = -1
iv_b_checked = -1


def read_files(key_file_a, key_file_b, key_file_c, key_file_d):
    global iv_a
    global iv_b
    global key_c
    global key_d
    global data
    global save_iv_a
    global save_iv_b
    # # #
    # key_file_a = 'C:/Users/PaulNikolaus/Desktop/file_A.txt'
    # key_file_b = 'C:/Users/PaulNikolaus/Desktop/file_B.txt'
    # key_file_c = 'C:/Users/PaulNikolaus/Desktop/file_C.txt'
    # key_file_d = 'C:/Users/PaulNikolaus/Desktop/file_D.txt'

    if key_file_a != '':
        with open(key_file_a, "r") as file:
            iv_a = file.read().upper()
    if key_file_b != '':
        with open(key_file_b, "r") as file:
            iv_b = file.read().upper()
    with open(key_file_c, "r") as file:
        key_c = file.read().upper()
    with open(key_file_d, "r") as file:
        key_d = file.read().upper()

    save_iv_b = iv_b
    save_iv_a = iv_a
    # print("Key D: " + key_d)
    # print("Key C: " + key_c)
    # print("IV B: " + iv_b)
    # print("IV A: " + iv_a)
    return


def start_decryption(name, data_file, direction):
    global data
    global enc_name
    # with open(data_file, "r") as file:
    #     data = file.read().upper()
    data = data_file.upper()
    # print(data)
    # print(direction)
    enc_name = name
    if enc_name.find("chacha") != -1:
        decrypted = start_chacha_decryption(direction)
        return str(decrypted)
    else:
        decrypted = start_aes_decryption(direction)
        return str(decrypted)


def prepare_iv_a(j):
    global iv_a
    global save_iv_a
    int_iv_a = int(save_iv_a, base=16)
    iv_a = hex(int_iv_a + j).upper()
    iv_a = iv_a[2:]
    if save_iv_a.startswith('0'):
        iv_a = '0' + iv_a


def prepare_iv_b(j):
    global iv_b
    global save_iv_b
    int_iv_b = int(save_iv_b, base=16)
    iv_b = hex(int_iv_b + j).upper()
    iv_b = iv_b[2:]
    if save_iv_b.startswith('0'):
        iv_b = '0' + iv_b


def start_aes_decryption(direction):
    global iv_a
    global iv_b
    global key_c
    global key_d
    global save_iv_a
    global save_iv_b
    global data
    packet_key = ''
    a = -1
    j = 0
    while j < 256:
        if iv_a_checked == -1:
            prepare_iv_a(j)
        if iv_b_checked == -1:
            prepare_iv_b(j)
        if direction == 0:
            a = 0
            packet_key = key_c
        if direction == -1:
            a = -1
            packet_key = key_d

        if a == 0 and len(data) > 0:
            decrypted = decrypt(iv_a, packet_key, data[8:], data[:8])
            if decrypted != '':
                return decrypted
        elif a != 0 and len(data) > 0:
            decrypted = decrypt(iv_b, packet_key, data[8:], data[:8])
            if decrypted != '':
                return decrypted
        j += 1


def start_chacha_decryption(direction):
    global key_c
    global key_d
    a = -1
    chacha_key_array = [key_c[64:], key_c[:64], key_d[64:], key_d[:64]]

    if direction == 0:
        a = 0
    if direction == -1:
        a = -1
    if a == 0:
        # print("\nVictim to Server packet")
        decrypted = chacha(chacha_key_array[0], chacha_key_array[1], data)
        return decrypted
    else:
        # print("\nServer to Victim packet")
        decrypted = chacha(chacha_key_array[2], chacha_key_array[3], data)
        return decrypted

def decrypt(iv, key, cipher, length):
    if enc_name.find("cbc") != -1 and len(cipher) > 0:
        return aes_cbc(iv, key, cipher)

    elif enc_name.find("ctr") != -1 and len(cipher) > 0:
        return aes_ctr(iv, key, cipher, length)

    elif enc_name.find("gcm") != -1 and len(cipher) > 0:
        return aes_gcm(iv, key, cipher)

    else:
        print("Cipher Method not supported!")
        print("Supported methods:")
        for x in Cipher_Enum:
            print(x.value)
        print("Please select a cipher from the list")
        sys.exit()


def aes_cbc(iv, key, cipher):
    # In cbc the block must be padded to 16 bit
    while len(cipher) % 32 != 0:
        cipher = cipher[:-1]
    key_hex = binascii.a2b_hex(key)
    iv_hex = binascii.a2b_hex(iv)
    aes = AES.new(key_hex, AES.MODE_CBC, iv_hex)
    decrypted = aes.decrypt(binascii.a2b_hex(cipher))
    print("Plaintext: " + decrypted)
    return iv


def aes_ctr(iv, key, cipher, length):
    global iv_a
    global iv_b
    global iv_a_checked
    global iv_b_checked
    key_hex = binascii.a2b_hex(key.rstrip())
    # # bytes.fromhex(some_hex_string)
    iv_hex = binascii.a2b_hex(iv.rstrip())

    aes = AES.new(key_hex, AES.MODE_CTR, initial_value=iv_hex, nonce=b'')
    decrypted = aes.decrypt(binascii.a2b_hex(cipher.rstrip()))
    save_iv = iv
    iv_int = int(iv, base=16)
    iv = hex(iv_int + int(len(cipher) / 32)).upper()
    iv = iv[2:]
    if save_iv.startswith('0'):
        iv = '0' + iv

    if decrypted.find(b'\x00\x00\x00\x00\x00\x00\x00') != -1 and iv.startswith(iv_a[:6]):
        iv_a_checked = 0
        padding_length = int.from_bytes(decrypted[:-(len(decrypted) - 1)], byteorder='big')
        # print("\nVictim to Server packet")
        print(decrypted)
        decrypted = decrypted[:-8]
        print("Cutted data: ", decrypted[10:-padding_length])
        # print(length)
        return decrypted[10:-padding_length]
    elif decrypted.find(b'\x00\x00\x00\x00\x00\x00\x00') != -1 and iv.startswith(iv_b[:6]):
        iv_b_checked = 0
        padding_length = int.from_bytes(decrypted[:-(len(decrypted) - 1)], byteorder='big')
        # print("\nServer to Victim packet")
        print(decrypted)
        decrypted = decrypted[:-8]
        print("Cutted data: ", decrypted[10:-padding_length])
        # print(length)
        return decrypted[10:-padding_length]

    if iv_b_checked and iv.startswith(iv_b[:6]):
        iv_b = iv
    if iv_a_checked and iv.startswith(iv_a[:6]):
        iv_a = iv
    return ''

def aes_gcm(iv, key, cipher):
    global iv_a
    global iv_b
    global iv_a_checked
    global iv_b_checked
    key_hex = binascii.a2b_hex(key.rstrip())
    iv_hex = binascii.a2b_hex(iv.rstrip())
    aes = AES.new(key_hex, AES.MODE_GCM, nonce=iv_hex)
    decrypted = aes.decrypt(binascii.a2b_hex(cipher.rstrip()))
    save_iv = iv
    iv_int = int(iv, base=16)
    iv = hex(iv_int + 1).upper()
    iv = iv[2:]
    if save_iv.startswith('0'):
        iv = '0' + iv

    if decrypted.find(b'\x00\x00\x00\x00\x00\x00\x00') != -1 and iv.startswith(iv_b[:6]) != -1:
        iv_a_checked = 0
        padding_length = int.from_bytes(decrypted[:-(len(decrypted) - 1)], byteorder='big')
        print("Cutted data: ", decrypted[10:-padding_length])
        return decrypted[10:-padding_length]
    elif decrypted.find(b'\x00\x00\x00\x00\x00\x00\x00') != -1 and iv.startswith(iv_a[:6]) != -1:
        iv_b_checked = 0
        padding_length = int.from_bytes(decrypted[:-(len(decrypted) - 1)], byteorder='big')
        print("Cutted data: ", decrypted[10:-padding_length])
        return decrypted[10:-padding_length]
    if iv_b_checked and iv.startswith(iv_b[:6]):
        iv_b = iv
    if iv_a_checked and iv.startswith(iv_a[:6]):
        iv_a = iv
    return ''


def chacha(key1, key2, cipher):
    seqnr = 0
    i = 0
    decrypted = -1
    ciphertext = ''
    while i < 100:
        seqnr += 1
        # bytes.fromhex(some_hex_string)
        key1_hex = binascii.a2b_hex(key1.rstrip())
        key2_hex = binascii.a2b_hex(key2.rstrip())
        nonce = int(seqnr).to_bytes(8, 'big')
        cipher_len = ChaCha20.new(key=key1_hex, nonce=nonce)
        length = cipher_len.decrypt(binascii.a2b_hex(cipher[:8].rstrip()))
        if length.find(b'\x00\x00') != -1:
            mac = Poly1305.new(key=key2_hex, nonce=nonce, cipher=ChaCha20, data=binascii.a2b_hex(cipher[:-32]))
            #if cipher[-32:] == mac.hexdigest().upper():
                # print("Mac is valid")
            hex_length = binascii.b2a_hex(length)
            # print("Data Length: " + repr(int(hex_length, 16)) + " Bytes")
            cipher_chacha = ChaCha20.new(key=key2_hex, nonce=int(seqnr).to_bytes(8, 'big'))
            cipher_chacha.seek(64)
            ciphertext = cipher_chacha.decrypt(binascii.a2b_hex(cipher[8:-32]))
            print(ciphertext)
            padding_length = int.from_bytes(ciphertext[:-(len(ciphertext) - 1)], byteorder='big')
            print("Cutted data: ", ciphertext[10:-padding_length])
            decrypted = 0
            ciphertext = ciphertext[10:-padding_length]

        i += 1
    # if decrypted == -1:
    #     print("Ack packet")
    return ciphertext


if __name__ == '__main__':
    read_files('', '', '', '')
    start_decryption('aes-ctr', 'C:/Users/PaulNikolaus/Desktop/tcpdump.txt', 0)
