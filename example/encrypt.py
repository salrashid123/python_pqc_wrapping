from python_pqc_wrapping import BaseWrapper

public_key_file_path= 'certs/pub-ml-kem-768-bare-seed.pem'

## for kms:
#public_key_file_path= 'certs/pub-ml-kem-768-kms.pem'

with open(public_key_file_path, 'r') as f:
    public_key_string = f.read()

client_data = '{"foo":"bar"}'
be = BaseWrapper(publicKey=public_key_string,keyName="mykey", clientData=client_data, decrypt=False)

en = be.encrypt(plaintext="foo".encode('utf-8'), aad="myaad".encode('utf-8'))
print(en)

with open('/tmp/encrypted.json', 'wb') as f:
    f.write(en.encode('utf-8'))

