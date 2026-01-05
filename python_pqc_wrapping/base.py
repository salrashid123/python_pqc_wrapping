
from python_pqc_wrapping.pqcwrappb.wrap_pb2 import Secret
from python_pqc_wrapping.pqcwrappb.blobwrap_pb2 import BlobInfo, KeyInfo
from google.protobuf.struct_pb2 import Struct
from python_pqc_wrapping.common import PEMUtility, mlkem_768_oidstring,mlkem_1024_oidstring
from google.protobuf import json_format

import os
import oqs
import json
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.protobuf.json_format import Parse

class BaseWrapper():

    DEFAULT_IV_SIZE = 12
    VERSION = 2

    def __init__(
        self,
        publicKey=None,
        privateKey=None,
        clientData=None,
        keyName=None,
        decrypt=False
    ) ->  Tuple[str,bytes]:
        self._clientData = clientData
        self._decrypt = decrypt
        self._keyName = keyName

        p = PEMUtility()
        if decrypt:
           self._private_alg, self._private = p.get_private_key(privateKey)            
        else:
           self._public_alg, self._public = p.get_public_key(publicKey)

    def encrypt(self, plaintext, aad=None, clientData=None) -> str:
        if self._public is None:
            raise Exception("BaseWrapper must be initialized with a public key for encryption")
        
        if self._public_alg == mlkem_768_oidstring:
            kemalg = "ML-KEM-768"
            secret_type = Secret.ml_kem_768
        elif self._public_alg== mlkem_1024_oidstring:
            kemalg = "ML-KEM-1024"
            secret_type = Secret.ml_kem_1024
        else:
            raise Exception("unsupported public key algorithm [{}] got must be one of [{}] [{}]".format(self._public_alg, mlkem_768_oidstring, mlkem_1024_oidstring))

        with oqs.KeyEncapsulation(kemalg) as server:
            # key = AESGCM.generate_key(bit_length=256)
            ciphertext, shared_secret_server = server.encap_secret(self._public)           
            aesgcm = AESGCM(shared_secret_server)
            nonce = os.urandom(self.DEFAULT_IV_SIZE)
            ct = nonce + aesgcm.encrypt(nonce, plaintext, aad)

            wrappb = Secret(name=self._keyName, 
                            version=self.VERSION,
                            type=secret_type,
                            kemCipherText=ciphertext)
                            
            secret_json = json_format.MessageToJson(wrappb, indent=0)


            client_data_dict = json.loads(self._clientData)
            client_data_struct = Struct()
            client_data_struct.update(client_data_dict)

            blobpb = BlobInfo(
                ciphertext = ct,
                key_info = KeyInfo(
                    mechanism = secret_type,
                    key_id=self._keyName,
                    wrapped_key=secret_json.encode('utf-8')
                ),
                client_data=client_data_struct
            )

            return json_format.MessageToJson(blobpb)
    
    def decrypt(self, blob_info, aad=None, clintData=None) -> str:
        if self._private is None:
            raise Exception("BaseWrapper must be initialized with a private key for decryption")
        if blob_info is None:
            raise Exception("BaseWrapper must be initialized with a blobInfo")
        
        if self._private_alg == mlkem_768_oidstring:
            kemalg = "ML-KEM-768"
            secret_type = Secret.ml_kem_768
        elif self._private_alg== mlkem_1024_oidstring:
            kemalg = "ML-KEM-1024"
            secret_type = Secret.ml_kem_1024
        else:
            raise Exception("unsupported private key algorithm [{}] got must be one of [{}] [{}]".format(self._private_alg, mlkem_768_oidstring, mlkem_1024_oidstring))

        blob_info_message = BlobInfo()
        bi = Parse(blob_info, blob_info_message)
        ivAndcipherText = bi.ciphertext

        secret_message = Secret()
        ki = Parse(bi.key_info.wrapped_key, secret_message)

        if ki.type != secret_type:
            raise Exception("Secret type provided in the key {} does not match private key type {}",ki.type, secret_type)
        
        with oqs.KeyEncapsulation(kemalg) as client:
            _ =  client.generate_keypair_seed(seed=self._private)
            shared_secret_client = client.decap_secret(ki.kemCipherText)  

            aesgcm = AESGCM(shared_secret_client)
            iv = ivAndcipherText[:self.DEFAULT_IV_SIZE]
            cipherText = ivAndcipherText[self.DEFAULT_IV_SIZE:]

            return aesgcm.decrypt(iv, cipherText, aad)
     
