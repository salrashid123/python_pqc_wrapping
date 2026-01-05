import pem
import asn1tools
import base64
from typing import Tuple

mlkem_512_oidstring = "2.16.840.1.101.3.4.4.1"
mlkem_768_oidstring = "2.16.840.1.101.3.4.4.2"
mlkem_1024_oidstring = "2.16.840.1.101.3.4.4.3"

class PEMUtility():
    _private_asn_spec = """
    PKCS8-PRIVATE-KEY-INFO DEFINITIONS ::= BEGIN
        PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey,
        attributes           [0]  IMPLICIT Attributes OPTIONAL 
        }
        
        Version ::= INTEGER { v1(0) }

        AlgorithmIdentifier ::=  SEQUENCE  {
            algorithm            OBJECT IDENTIFIER,
            parameter            ANY DEFINED BY algorithm OPTIONAL 
        }      
        Attribute ::= SEQUENCE {
            attrType          OBJECT IDENTIFIER,
            attrValues        SET OF ANY
        }

        PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier

        PrivateKey ::= OCTET STRING

        Attributes ::= SET OF Attribute

    END
    """


    _public_asn_spec = """
    PKCS8-PUBLIC-KEY-INFO DEFINITIONS ::= BEGIN
        SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm AlgorithmIdentifier,
            subjectPublicKey BIT STRING
        }
        
        AlgorithmIdentifier ::=  SEQUENCE  {
            algorithm            OBJECT IDENTIFIER,
            parameter            ANY DEFINED BY algorithm OPTIONAL 
        }      
    END
    """

    def __init__(
        self,
        debug=False,
    ):
        self._debug = debug
        self._pkcs8_public_spec = asn1tools.compile_string(self._public_asn_spec)
        self._pkcs8_private_spec = asn1tools.compile_string(self._private_asn_spec)

    def get_public_key(self, pem_string) -> Tuple[str,bytes]:
        try:
            pem_object = pem.parse(pem_string)
            encoded_bytes = pem_object[0].bytes_payload
            f = base64.b64decode(encoded_bytes) 
            decoded_key = self._pkcs8_public_spec.decode('SubjectPublicKeyInfo', f)
            alg = decoded_key['algorithm']['algorithm']               
        except Exception as e:
            print(f"Error decoding ASN.1 public key: {e}")
            raise e
        if alg == mlkem_512_oidstring:
            raise Exception("MLKEM 512 not supported")
        elif alg == mlkem_768_oidstring:
            pass
        elif alg == mlkem_1024_oidstring:
            pass
        else:
            raise Exception("unknown algorithm {}",alg)
        return alg, bytes(decoded_key['subjectPublicKey'][0])


    def get_private_key(self, pem_string) -> Tuple[str,bytes]:
        try:
            pem_object = pem.parse(pem_string)
            encoded_bytes = pem_object[0].bytes_payload
            f = base64.b64decode(encoded_bytes)     
            decoded_key = self._pkcs8_private_spec.decode('PrivateKeyInfo', f)
            alg = decoded_key['privateKeyAlgorithm']['algorithm']                 
        except Exception as e:
            print(f"Error decoding ASN.1 private key: {e}")
            raise e
        if alg == mlkem_512_oidstring:
            raise Exception("MLKEM 512 not supported")
        elif alg == mlkem_768_oidstring:
            pass
        elif alg == mlkem_1024_oidstring:
            pass
        else:
            raise Exception("unknown algorithm {}",alg)        
        return alg, bytes(decoded_key['privateKey'])
