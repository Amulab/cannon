from impacket import system_errors
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException

from .base import BulletGenerator


class IsPathSupported(NDRCALL):
    """
    Structure to make the RPC call to IsPathSupported() in [MS-FSRVP Protocol](
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
    """
    opnum = 8
    structure = (
        ('ShareName', WSTR),  # Type: LPWSTR
    )


class IsPathSupportedResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to IsPathSupported() in [MS-FSRVP Protocol](
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
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
    Structure to parse the response of the RPC call to IsPathShadowCopied() in [MS-FSRVP Protocol](
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b)
    """
    structure = ()


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'FSRVP SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'FSRVP SessionError: unknown error code: 0x%x' % self.error_code


bullet_generators = [
    BulletGenerator(IsPathSupported, {}, ['ShareName']),
    BulletGenerator(IsPathShadowCopied, {}, ['ShareName'])
]
