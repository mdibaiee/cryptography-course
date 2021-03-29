from binascii import hexlify, unhexlify
from math import ceil
from Crypto.Cipher import AES
from Crypto import Random

cases = [{
    'key': '140b41b22a29beb4061bda66b6747e14',
    'ciphertext': '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81',
}, {
    'key': '140b41b22a29beb4061bda66b6747e14',
    'ciphertext': '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253',
}, {
    'key': '36f18357be4dbd77f050515c73fcf9f2',
    'ciphertext': '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329',
}, {
    'key': '36f18357be4dbd77f050515c73fcf9f2',
    'ciphertext': '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'
}]


rnd = Random.new()


def xor(a, b):
    if len(a) > len(b):
        return bytes([x ^ y for (x, y) in zip(a[:len(b)], b)])
    else:
        return bytes([x ^ y for (x, y) in zip(a, b[:len(a)])])


# CBC: Cipher Block Chaining
def cbc_enc(key, message):
    m = unhexlify(message)
    iv = rnd.read(AES.block_size)
    k = unhexlify(key)

    block_number = ceil(len(m) / AES.block_size)
    cipher = AES.new(k, AES.MODE_ECB)

    step = iv
    result = bytes()
    for i in range(block_number):
        block = m[i*AES.block_size:(i+1)*AES.block_size]
        step = cipher.encrypt(xor(block, step))
        result = result + step

    return hexlify(result)


def cbc_dec(key, message):
    m = unhexlify(message)
    iv = m[0:AES.block_size]
    m = m[AES.block_size:]
    k = unhexlify(key)

    block_number = ceil(len(m) / AES.block_size)
    cipher = AES.new(k, AES.MODE_ECB)

    r = iv
    result = bytes()
    for i in range(block_number):
        block = m[i*AES.block_size:(i+1)*AES.block_size]
        decrypted_block = xor(cipher.decrypt(block), r)

        r = block
        result = result + decrypted_block
        if i == block_number-1:
            last_byte = decrypted_block[-1]
            result = result[0:-last_byte]

    return result


# CTR: Counter-mode
def ctr_dec(key, message):
    m = unhexlify(message)
    iv = m[0:AES.block_size]
    m = m[AES.block_size:]
    k = unhexlify(key)

    block_number = ceil(len(m) / AES.block_size)
    cipher = AES.new(k, AES.MODE_ECB)

    result = bytes()
    for i in range(block_number):
        block = m[i*AES.block_size:(i+1)*AES.block_size]
        new_iv = (int.from_bytes(iv, 'big') + i).to_bytes(AES.block_size, 'big')
        decrypted_block = xor(cipher.encrypt(new_iv), block)

        result = result + decrypted_block

    return result


# first two cases are CBC
for c in cases[0:2]:
    print(cbc_dec(c['key'], c['ciphertext']))


for c in cases[2:]:
    print(ctr_dec(c['key'], c['ciphertext']))
