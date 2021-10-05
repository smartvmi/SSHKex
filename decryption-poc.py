# AES-CTR

key_hex = binascii.a2b_hex(key)
iv_hex = binascii.a2b_hex(iv)
aes = AES.new(key_hex, AES.MODE_CTR, 
initial_value=iv_hex, nonce=b'')
decrypted = aes.decrypt(binascii.a2b_hex(cipher))
save_iv = iv
iv_int = int(iv, base=16)
iv = hex(iv_int + int(len(cipher) / 32)).upper()
iv = iv[2:]

# AES-GCM
key_hex = binascii.a2b_hex(key)
iv_hex = binascii.a2b_hex(iv)
aes = AES.new(key_hex, AES.MODE_GCM, nonce=iv_hex)
decrypted = aes.decrypt(binascii.a2b_hex(cipher))

# IV adjustment for CTR + GCM

int_iv_a = int(save_iv_a, base=16)
iv_a = hex(int_iv_a + j).upper()
iv_a = iv_a[2:]
if save_iv_a.startswith('0'):
   iv_a = '0' + iv_a

# ChaCha20
nonce = int(seqnr).to_bytes(8, 'big')
cipher_len = ChaCha20.new(key=key1_hex, nonce=nonce)
length = cipher_len.decrypt(binascii.a2b_hex(cipher[:8]))
   if length.find(b'\x00\x00') != -1:
      mac = Poly1305.new(key=key2_hex, nonce=nonce, 
      cipher=ChaCha20, data=binascii.a2b_hex(cipher[:-32]))
      if cipher[-32:] == mac.hexdigest().upper():
          print("Mac is valid")
      hex_length = binascii.b2a_hex(length)
      cipher_chacha = ChaCha20.new(key=key2_hex, 
      nonce=int(seqnr).to_bytes(8, 'big'))
      cipher_chacha.seek(64)
      decrypted = cipher_chacha.decrypt(binascii.
      	a2b_hex(cipher[8:-32]))

# AES CBC
while len(cipher) % 32 != 0:
    cipher = cipher[:-1]
key_hex = binascii.a2b_hex(key)
iv_hex = binascii.a2b_hex(iv)
aes = AES.new(key_hex, AES.MODE_CBC, iv_hex)
decrypted = aes.decrypt(binascii.a2b_hex(cipher))
print("Plaintext: " + decrypted)
return iv