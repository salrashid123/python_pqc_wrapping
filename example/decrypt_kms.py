from python_pqc_wrapping import BaseWrapper

private_key_file_path= 'gcpkms://projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1'

with open("/tmp/encrypted.json", 'r') as file:
    encrypted_data = file.read()

client_data = '{"foo":"bar"}'
bd = BaseWrapper(privateKey=private_key_file_path, clientData=client_data)

dn = bd.decrypt(blob_info=encrypted_data, aad="myaad".encode('utf-8'))
print(dn.decode())


