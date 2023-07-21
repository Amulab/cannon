from impacket.dcerpc.v5.even import ElfrOpenBELW
from impacket.dcerpc.v5.dtypes import NULL

from .base import BulletGenerator

bullet_generators = [
    BulletGenerator(ElfrOpenBELW, {
        'MajorVersion': 1,
        'MinorVersion': 1,
        'UNCServerName': NULL
    }, ['BackupFileName'])
]
