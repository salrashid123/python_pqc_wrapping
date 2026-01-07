from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Secret(_message.Message):
    __slots__ = ["kdfSalt", "kemCipherText", "name", "publicKey", "type", "version"]
    class KeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    KDFSALT_FIELD_NUMBER: _ClassVar[int]
    KEMCIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PUBLICKEY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    kdfSalt: bytes
    kemCipherText: bytes
    ml_kem_1024: Secret.KeyType
    ml_kem_512: Secret.KeyType
    ml_kem_768: Secret.KeyType
    name: str
    publicKey: bytes
    type: Secret.KeyType
    version: int
    def __init__(self, name: _Optional[str] = ..., version: _Optional[int] = ..., type: _Optional[_Union[Secret.KeyType, str]] = ..., kemCipherText: _Optional[bytes] = ..., kdfSalt: _Optional[bytes] = ..., publicKey: _Optional[bytes] = ...) -> None: ...
