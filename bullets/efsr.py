from impacket import system_errors
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTERNULL
from impacket.dcerpc.v5.dtypes import ULONG, WSTR, DWORD, LONG, BOOL, PCHAR, RPC_SID, LPWSTR
from impacket.dcerpc.v5.rpcrt import DCERPCException

from .base import BulletGenerator


class EfsHashBlob(NDRSTRUCT):
    structure = (
        ('Data', DWORD),
        ('cbData', PCHAR),
    )


class EncryptionCertificateHash(NDRSTRUCT):
    structure = (
        ('Lenght', DWORD),
        ('SID', RPC_SID),
        ('Hash', EfsHashBlob),
        ('Display', LPWSTR),
    )


class EncryptionCertificateList(NDRSTRUCT):
    structure = (
        ('nUsers', DWORD),
        ('Users', EncryptionCertificateHash),
    )


class EfsRpcOpenFileRaw(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcOpenFileRaw() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 0
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
        ('Flags', LONG),  # Type: long
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcOpenFileRaw() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcEncryptFileSrv(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcEncryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 4
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
    )


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcEncryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcDecryptFileSrv(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 5
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
        ('OpenFlag', ULONG),  # Type: unsigned
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcQueryUsersOnFile(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcQueryUsersOnFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 6
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
    )


class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcQueryUsersOnFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcQueryRecoveryAgents(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcQueryRecoveryAgents() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 7
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
    )


class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcQueryRecoveryAgents() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcRemoveUsersFromFile(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/28609dad-5fa5-4af9-9382-18d40e3e9dec)
    """
    opnum = 8
    structure = (
        ('FileName', WSTR),
        ('Users', EncryptionCertificateList)
    )


class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcRemoveUsersFromFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcAddUsersToFile(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcAddUsersToFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/afd56d24-3732-4477-b5cf-44cc33848d85)
    """
    opnum = 9
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
        ('EncryptionCertificates', EncryptionCertificateList)
    )


class EfsRpcAddUsersToFileResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcDecryptFileSrv() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcFileKeyInfo(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 12
    structure = (
        ('FileName', WSTR),  # Type: wchar_t *
        ('InfoClass', DWORD)  # Type: DWORD
    )


class EfsRpcFileKeyInfoResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcFileKeyInfo() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    """
    Structure to make the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    opnum = 13
    structure = (
        ('SrcFileName', WSTR),  # Type: wchar_t *
        ('DestFileName', WSTR),  # Type: wchar_t *
        ('dwCreationDisposition', DWORD),  # Type: DWORD
        ('dwAttributes', DWORD),  # Type: DWORD
        ('RelativeSD', EfsHashBlob),  # Type: EFS_RPC_BLOB *
        ('bInheritHandle', BOOL),  # Type: BOOL
    )


class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    """
    Structure to parse the response of the RPC call to EfsRpcDuplicateEncryptionInfoFile() in [MS-EFSR Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)
    """
    structure = ()


class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ('dwFlags', DWORD),  # Type: DWORD
        # Accroding to this page: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/d36df703-edc9-4482-87b7-d05c7783d65e
        # Reserved must be set to NULL
        ('Reserved', NDRPOINTERNULL),  # Type: NDRPOINTERNULL *
        ('FileName', WSTR),  # Type: wchar_t *
        ('EncryptionCertificates', EncryptionCertificateList),  # Type: ENCRYPTION_CERTIFICATE_LIST *
    )


class EfsRpcAddUsersToFileExResponse(NDRCALL):
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
    BulletGenerator(EfsRpcOpenFileRaw, {'Flags': 0}, ['FileName']),
    BulletGenerator(EfsRpcEncryptFileSrv, {}, ['FileName']),
    BulletGenerator(EfsRpcDecryptFileSrv, {'OpenFlag': 0}, ['FileName']),
    BulletGenerator(EfsRpcQueryUsersOnFile, {}, ['FileName']),
    BulletGenerator(EfsRpcQueryRecoveryAgents, {}, ['FileName']),
    BulletGenerator(EfsRpcRemoveUsersFromFile, {}, ['FileName']),
    BulletGenerator(EfsRpcAddUsersToFile, {}, ['FileName']),
    BulletGenerator(EfsRpcFileKeyInfo, {'InfoClass': 0}, ['FileName']),
    BulletGenerator(EfsRpcDuplicateEncryptionInfoFile, {'dwCreationDisposition': 0,
                                                        'dwAttributes': 0,
                                                        'bInheritHandle': 0,
                                                        'RelativeSD': EfsHashBlob()},
                    ['SrcFileName', 'DestFileName']),
    BulletGenerator(EfsRpcAddUsersToFileEx, {'dwFlags': 0x00000002}, ['FileName']),
]
