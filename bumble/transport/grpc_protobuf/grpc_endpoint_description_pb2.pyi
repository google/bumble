from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Credentials(_message.Message):
    __slots__ = ["pem_cert_chain", "pem_private_key", "pem_root_certs"]
    PEM_CERT_CHAIN_FIELD_NUMBER: _ClassVar[int]
    PEM_PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    PEM_ROOT_CERTS_FIELD_NUMBER: _ClassVar[int]
    pem_cert_chain: str
    pem_private_key: str
    pem_root_certs: str
    def __init__(self, pem_root_certs: _Optional[str] = ..., pem_private_key: _Optional[str] = ..., pem_cert_chain: _Optional[str] = ...) -> None: ...

class Endpoint(_message.Message):
    __slots__ = ["required_headers", "target", "tls_credentials"]
    REQUIRED_HEADERS_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    TLS_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    required_headers: _containers.RepeatedCompositeFieldContainer[Header]
    target: str
    tls_credentials: Credentials
    def __init__(self, target: _Optional[str] = ..., tls_credentials: _Optional[_Union[Credentials, _Mapping]] = ..., required_headers: _Optional[_Iterable[_Union[Header, _Mapping]]] = ...) -> None: ...

class Header(_message.Message):
    __slots__ = ["key", "value"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
