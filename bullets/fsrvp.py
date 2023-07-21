from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR

from .base import BulletGenerator


class IsPathSupported(NDRCALL):
    """
    Structure to make the RPC call to IsPathSupported() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
    """
    opnum = 8
    structure = (
        ('ShareName', WSTR),  # Type: LPWSTR
    )


class IsPathSupportedResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to IsPathSupported() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
    """
    structure = ()


class IsPathShadowCopied(NDRCALL):
    """
    Structure to make the RPC call to IsPathShadowCopied() in MS-FSRVP Protocol
    """
    opnum = 9
    structure = (
        ('ShareName', WSTR),  # Type: LPWSTR
    )


class IsPathShadowCopiedResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to IsPathShadowCopied() in [MS-FSRVP Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
    """
    structure = ()


bullet_generators = [
    BulletGenerator(IsPathSupported, {}, ['ShareName']),
    BulletGenerator(IsPathShadowCopied, {}, ['ShareName'])
]