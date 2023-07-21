import base64
import logging

from certipy.lib.target import Target
from impacket import ntlm
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import MSRPCHeader


def get_all_dcs(target: Target):
    target_domain = target.domain
    if not target_domain:
        logging.debug(f'target domain not specified try get domain name by ntlm info:')
        target_domain = ntlm_info(target.target_ip)[ntlm.NTLMSSP_AV_DNS_DOMAINNAME]
        logging.debug(f'domain name retrived: {target_domain}')
    super_resolver = target.resolver.resolver

    if not all([target_domain, super_resolver.nameservers]):
        logging.error('you must specify domain name and a nameserver')
        return []
    try:
        aws = target.resolver.resolver.resolve(target_domain)
        logging.debug(f'got dc ips: {list(aws)}')
        return [str(aw) for aw in list(aws)]
    except Exception as e:
        logging.error(f'some error happened resolving domain name: {e}')
        return []


def ntlm_info(target_ip, method='rpc'):
    available_method = {'smb': f'ncacn_np:{target_ip}[\\PIPE\\netlogon]',
                        'rpc': f'ncacn_ip_tcp:{target_ip}[135]',
                        'ldap': f''}
    target_info = {ntlm.NTLMSSP_AV_DNS_HOSTNAME: '',
                   ntlm.NTLMSSP_AV_DNS_DOMAINNAME: '',
                   ntlm.NTLMSSP_AV_DNS_TREENAME: '',
                   ntlm.NTLMSSP_AV_HOSTNAME: ''}

    bind_data = base64.b64decode('BQALAxAAAABwACAAAQAAALgQuBAAAAAAAQAAAAAAAQAIg6/hH13JEZGkCAArFKD6AwAAAARdiIrr'
                                 'HMkRn+gIACsQSGACAAAACgIAAAAAAABOVExNU1NQAAEAAAAFAoigAAAAAAAAAAAAAAAAAAAAAA==')
    if method not in available_method:
        logging.error(f'available methods: {available_method}')
    if method != 'ldap':
        c = transport.DCERPCTransportFactory(available_method.get(method))
        c.connect()
        c.send(bind_data)
        s = c.recv()
        if s:
            # logger.debug(s)
            resp = MSRPCHeader(s)
            auth_data = resp['auth_data']
            challenge_msg = ntlm.NTLMAuthChallenge(auth_data)
            av_pairs = ntlm.AV_PAIRS(challenge_msg['TargetInfoFields'])
            for k in target_info:
                _, av_data = av_pairs[k]
                target_info[k] = av_data.decode('utf-16')
            logging.debug(target_info)
        else:
            logging.error(f'no data received')

    else:
        pass

    return target_info