# GetFGPP

Dumps Fine Grained Password Policies (FGPP) from Active Directory via LDAP.

Requires read access to the Password Settings Container — by default only admins have this right, but it's occasionally misconfigured.

## Install

```bash
pip3 install ldap3
```

(`python-dateutil` no longer required)

## Usage

```
usage: fgpp.py [-h] -l LDAPSERVER -d DOMAIN [-u USERNAME] [-p PASSWORD]
               [-H HASHES] [--use-ldaps] [--kerberos] [--port PORT]

options:
  -l, --ldapserver   LDAP server (hostname or IP)
  -d, --domain       AD domain (e.g. corp.local)
  -u, --username     LDAP username
  -p, --password     LDAP password
  -H, --hashes       NTLM hashes (lmhash:nthash or :nthash)
  --use-ldaps        Use LDAPS (SSL/TLS)
  --kerberos         Use Kerberos (GSSAPI)
  --port             Custom port (default: 389 or 636)
```

## Examples

**Password auth:**
```
python3 fgpp.py -l dc01.corp.local -d corp.local -u Administrator -p Password123
```

**Pass-the-hash:**
```
python3 fgpp.py -l 10.10.10.1 -d corp.local -u Administrator -H :aabbccddeeff00112233445566778899
```

**LDAPS:**
```
python3 fgpp.py -l dc01.corp.local -d corp.local -u jdoe -p Password123 --use-ldaps
```

**Kerberos (requires valid TGT):**
```
python3 fgpp.py -l dc01.corp.local -d corp.local --kerberos
```

## Sample Output

```
[*] Using NTLM authentication for corp.local\Administrator...
[+] LDAP bind successful.

[*] Searching for Fine Grained Password Policies...

[+] 2 FGPP policies found.

Policy Name:                  DA Policy
Precedence (lower = higher):  1
Minimum Password Length:      14
Password History Length:      24
Complexity Enabled:           TRUE
Reversible Encryption:        FALSE
Minimum Password Age:         1 days 0 hours 0 minutes 0 seconds
Maximum Password Age:         42 days 0 hours 0 minutes 0 seconds
Lockout Threshold:            3
Observation Window:           0 days 0 hours 30 minutes 0 seconds
Lockout Duration:             0 days 1 hours 0 minutes 0 seconds
Policy Applies To:            CN=Domain Admins,CN=Users,DC=corp,DC=local

Policy Name:                  DU Policy
Precedence (lower = higher):  2
Minimum Password Length:      6
Password History Length:      0
Complexity Enabled:           FALSE
Reversible Encryption:        TRUE
...
```
