def encrypt(string, password):
    pad = lambda s : s + str.encode(chr(16 - len(s) % 16) * (16 - len(s) % 16))

    password = str.encode(password)
    string = str.encode(string)

    salt = os.urandom(8) # Unpredictable enough for cryptographic use
    salted = b''
    dx = b''

    while len(salted) < 48:
        dx = md5_encode(dx + password + salt, True)
        salted += dx

    key = salted[0:32]
    iv = salted[32:48]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_64 = base64.b64encode(cipher.encrypt(pad(string))).decode('ascii')
    
    json_data = {
        'ct': encrypted_64,
        'iv': iv.hex(),
        's': salt.hex()
    }

    return json.dumps(json_data, separators = (',', ':'))

def decrypt(data, password):
    unpad = lambda s : s[:-s[-1]]

    data = json.loads(data)
    password = password.encode('latin-1')
    ct = base64.b64decode(data['ct'])

    try:
        salt = hex2str(data['s'])
        iv = hex2str(data['iv'])
    except:
        return False

    concatedPassphrase = password + salt

    md5 = [None, None, None]
    md5[0] = md5_encode(concatedPassphrase, True)

    result = md5[0]

    for i in range(1,3):
        md5[i] = md5_encode(md5[i - 1] + concatedPassphrase, True)
        result += md5[i]

    key = result[0:32]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ct)
    clean = unpad(decrypted).decode('ascii').rstrip()
    
    return clean
