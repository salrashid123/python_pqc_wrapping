from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

Aes256: KeyType
Bytes: KeyEncoding
DESCRIPTOR: _descriptor.FileDescriptor
Decrypt: KeyPurpose
Ed25519: KeyType
EdsaP256: KeyType
EdsaP384: KeyType
EdsaP521: KeyType
Encrypt: KeyPurpose
HMAC: KeyType
KeyPurpose_Unknown: KeyPurpose
MAC: KeyPurpose
Pkcs8: KeyEncoding
Pkix: KeyEncoding
Rsa2048: KeyType
Rsa3072: KeyType
Rsa4096: KeyType
Sha224: HmacType
Sha256: HmacType
Sha384: HmacType
Sha512: HmacType
Sign: KeyPurpose
Unknown_HmacType: HmacType
Unknown_KeyEncoding: KeyEncoding
Unknown_KeyType: KeyType
Unwrap: KeyPurpose
Verify: KeyPurpose
Wrap: KeyPurpose

class BlobInfo(_message.Message):
    __slots__ = ["ciphertext", "client_data", "hmac", "iv", "key_info", "plaintext", "value_path", "wrapped"]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    CLIENT_DATA_FIELD_NUMBER: _ClassVar[int]
    HMAC_FIELD_NUMBER: _ClassVar[int]
    IV_FIELD_NUMBER: _ClassVar[int]
    KEY_INFO_FIELD_NUMBER: _ClassVar[int]
    PLAINTEXT_FIELD_NUMBER: _ClassVar[int]
    VALUE_PATH_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    client_data: _struct_pb2.Struct
    hmac: bytes
    iv: bytes
    key_info: KeyInfo
    plaintext: bytes
    value_path: str
    wrapped: bool
    def __init__(self, ciphertext: _Optional[bytes] = ..., iv: _Optional[bytes] = ..., hmac: _Optional[bytes] = ..., wrapped: bool = ..., plaintext: _Optional[bytes] = ..., key_info: _Optional[_Union[KeyInfo, _Mapping]] = ..., value_path: _Optional[str] = ..., client_data: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...) -> None: ...

class EnvelopeInfo(_message.Message):
    __slots__ = ["ciphertext", "iv", "key"]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    IV_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    iv: bytes
    key: bytes
    def __init__(self, ciphertext: _Optional[bytes] = ..., key: _Optional[bytes] = ..., iv: _Optional[bytes] = ...) -> None: ...

class KeyInfo(_message.Message):
    __slots__ = ["flags", "hmac_key_id", "hmac_mechanism", "key", "key_encoding", "key_id", "key_purposes", "key_type", "mechanism", "wrapped_key", "wrapped_key_encoding"]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    HMAC_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    HMAC_MECHANISM_FIELD_NUMBER: _ClassVar[int]
    KEY_ENCODING_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_PURPOSES_FIELD_NUMBER: _ClassVar[int]
    KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    MECHANISM_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_KEY_ENCODING_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_KEY_FIELD_NUMBER: _ClassVar[int]
    flags: int
    hmac_key_id: str
    hmac_mechanism: int
    key: bytes
    key_encoding: KeyEncoding
    key_id: str
    key_purposes: _containers.RepeatedScalarFieldContainer[KeyPurpose]
    key_type: KeyType
    mechanism: int
    wrapped_key: bytes
    wrapped_key_encoding: KeyEncoding
    def __init__(self, mechanism: _Optional[int] = ..., hmac_mechanism: _Optional[int] = ..., key_id: _Optional[str] = ..., hmac_key_id: _Optional[str] = ..., wrapped_key: _Optional[bytes] = ..., flags: _Optional[int] = ..., key_type: _Optional[_Union[KeyType, str]] = ..., key_purposes: _Optional[_Iterable[_Union[KeyPurpose, str]]] = ..., key: _Optional[bytes] = ..., key_encoding: _Optional[_Union[KeyEncoding, str]] = ..., wrapped_key_encoding: _Optional[_Union[KeyEncoding, str]] = ...) -> None: ...

class Options(_message.Message):
    __slots__ = ["with_aad", "with_config_map", "with_disallow_env_vars", "with_iv", "with_key_encoding", "with_key_id", "with_key_purposes", "with_key_type", "with_random_bytes", "with_wrapped_key_encoding", "without_hmac"]
    class WithConfigMapEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    WITHOUT_HMAC_FIELD_NUMBER: _ClassVar[int]
    WITH_AAD_FIELD_NUMBER: _ClassVar[int]
    WITH_CONFIG_MAP_FIELD_NUMBER: _ClassVar[int]
    WITH_DISALLOW_ENV_VARS_FIELD_NUMBER: _ClassVar[int]
    WITH_IV_FIELD_NUMBER: _ClassVar[int]
    WITH_KEY_ENCODING_FIELD_NUMBER: _ClassVar[int]
    WITH_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    WITH_KEY_PURPOSES_FIELD_NUMBER: _ClassVar[int]
    WITH_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    WITH_RANDOM_BYTES_FIELD_NUMBER: _ClassVar[int]
    WITH_WRAPPED_KEY_ENCODING_FIELD_NUMBER: _ClassVar[int]
    with_aad: bytes
    with_config_map: _containers.ScalarMap[str, str]
    with_disallow_env_vars: bool
    with_iv: bytes
    with_key_encoding: KeyEncoding
    with_key_id: str
    with_key_purposes: _containers.RepeatedScalarFieldContainer[KeyPurpose]
    with_key_type: KeyType
    with_random_bytes: bytes
    with_wrapped_key_encoding: KeyEncoding
    without_hmac: bool
    def __init__(self, with_key_id: _Optional[str] = ..., with_aad: _Optional[bytes] = ..., with_iv: _Optional[bytes] = ..., with_config_map: _Optional[_Mapping[str, str]] = ..., with_key_purposes: _Optional[_Iterable[_Union[KeyPurpose, str]]] = ..., with_key_type: _Optional[_Union[KeyType, str]] = ..., with_random_bytes: _Optional[bytes] = ..., with_key_encoding: _Optional[_Union[KeyEncoding, str]] = ..., with_wrapped_key_encoding: _Optional[_Union[KeyEncoding, str]] = ..., with_disallow_env_vars: bool = ..., without_hmac: bool = ...) -> None: ...

class SigInfo(_message.Message):
    __slots__ = ["hmac_type", "key_info", "signature"]
    HMAC_TYPE_FIELD_NUMBER: _ClassVar[int]
    KEY_INFO_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    hmac_type: HmacType
    key_info: KeyInfo
    signature: bytes
    def __init__(self, key_info: _Optional[_Union[KeyInfo, _Mapping]] = ..., signature: _Optional[bytes] = ..., hmac_type: _Optional[_Union[HmacType, str]] = ...) -> None: ...

class WrapperConfig(_message.Message):
    __slots__ = ["metadata"]
    class MetadataEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    METADATA_FIELD_NUMBER: _ClassVar[int]
    metadata: _containers.ScalarMap[str, str]
    def __init__(self, metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...

class HmacType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class KeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class KeyEncoding(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class KeyPurpose(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
