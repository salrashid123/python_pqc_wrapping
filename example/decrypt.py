from python_pqc_wrapping import BaseWrapper

private_key_file_path= 'certs/bare-seed-768.pem'
with open(private_key_file_path, 'r') as f:
    private_key_string = f.read()

with open("/tmp/encrypted.json", 'r') as file:
    encrypted_data = file.read()

client_data = '{"foo":"bar"}'
bd = BaseWrapper(privateKey=private_key_string, clientData=client_data, decrypt=True)

dn = bd.decrypt(blob_info=encrypted_data, aad="myaad".encode('utf-8'))
print(dn.decode())


