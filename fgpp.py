#!/usr/bin/env python3
import argparse
import ssl
import sys
from datetime import timedelta
from ldap3 import Server, Connection, NTLM, SASL, GSSAPI, ALL, SUBTREE, Tls
from ldap3.core.exceptions import LDAPException, LDAPBindError


def err(msg: str) -> None:
    print(msg, file=sys.stderr)


def base_creator(domain: str) -> str:
    return ','.join(f"DC={dc}" for dc in domain.split('.'))


def clock(nano: int) -> str:
    td = timedelta(seconds=int(abs(nano / 10_000_000)))
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days} days {hours} hours {minutes} minutes {seconds} seconds"


def connect(args: argparse.Namespace) -> Connection:
    use_ssl = args.use_ldaps
    port = args.port or (636 if use_ssl else 389)

    tls_config = Tls(validate=ssl.CERT_NONE)
    server = Server(
        args.ldapserver,
        port=port,
        use_ssl=use_ssl,
        get_info=ALL,
        tls=tls_config if use_ssl else None,
    )

    try:
        if args.kerberos:
            err("[*] Using Kerberos authentication (GSSAPI)...")
            conn = Connection(
                server,
                authentication=SASL,
                sasl_mechanism=GSSAPI,
                auto_bind=True,
            )
        else:
            if not args.username:
                raise ValueError("Username required for NTLM authentication.")

            user = f"{args.domain}\\{args.username}"

            if args.hashes:
                # Accept lmhash:nthash or just :nthash
                parts = args.hashes.split(':')
                lmhash = parts[0] if len(parts) == 2 else 'aad3b435b51404eeaad3b435b51404ee'
                nthash = parts[-1]
                password = f"{lmhash}:{nthash}"
                err(f"[*] Using NTLM pass-the-hash for {user}...")
            elif args.password:
                password = args.password
                err(f"[*] Using NTLM authentication for {user}...")
            else:
                raise ValueError("Password (-p) or hash (-H) required for NTLM authentication.")

            conn = Connection(
                server,
                user=user,
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )

        err("[+] LDAP bind successful.\n")
        return conn

    except LDAPBindError as e:
        raise ConnectionError(f"LDAP bind failed: {e}") from e
    except LDAPException as e:
        raise ConnectionError(f"LDAP error: {e}") from e


def get_attr(entry, attr: str, default: str = 'N/A') -> str:
    try:
        val = entry[attr]
        return str(val) if val else default
    except Exception:
        return default


def enumerate_fgpp(conn: Connection, domain: str) -> None:
    base = base_creator(domain)
    fgpp_base = f"CN=Password Settings Container,CN=System,{base}"

    err("[*] Searching for Fine Grained Password Policies...\n")
    conn.search(
        search_base=fgpp_base,
        search_filter='(objectClass=msDS-PasswordSettings)',
        attributes=['*'],
    )

    if not conn.entries:
        err("[-] No FGPP policies found.")
        return

    err(f"[+] {len(conn.entries)} FGPP policies found.\n")

    for entry in conn.entries:
        print(f"Policy Name:                  {get_attr(entry, 'name')}")
        desc = get_attr(entry, 'description', '')
        if desc:
            print(f"Description:                  {desc}")
        print(f"Precedence (lower = higher):  {get_attr(entry, 'msds-passwordsettingsprecedence')}")
        print(f"Minimum Password Length:      {get_attr(entry, 'msds-minimumpasswordlength')}")
        print(f"Password History Length:      {get_attr(entry, 'msds-passwordhistorylength')}")
        print(f"Complexity Enabled:           {get_attr(entry, 'msds-passwordcomplexityenabled')}")
        print(f"Reversible Encryption:        {get_attr(entry, 'msds-passwordreversibleencryptionenabled')}")

        try:
            print(f"Minimum Password Age:         {clock(int(entry['msds-minimumpasswordage'].value))}")
            print(f"Maximum Password Age:         {clock(int(entry['msds-maximumpasswordage'].value))}")
        except Exception:
            pass

        try:
            print(f"Lockout Threshold:            {get_attr(entry, 'msds-lockoutthreshold')}")
            print(f"Observation Window:           {clock(int(entry['msds-lockoutobservationwindow'].value))}")
            print(f"Lockout Duration:             {clock(int(entry['msds-lockoutduration'].value))}")
        except Exception:
            pass

        try:
            for target in entry['msds-psoappliesto']:
                print(f"Policy Applies To:            {target}")
        except Exception:
            pass

        print()


def enumerate_applied_objects(conn: Connection, domain: str) -> None:
    err("[*] Enumerating objects with FGPP applied...\n")
    base = base_creator(domain)
    conn.search(
        search_base=base,
        search_filter='(msDS-PSOApplied=*)',
        attributes=['distinguishedName', 'msDS-PSOApplied'],
    )

    if not conn.entries:
        err("[-] No objects with applied FGPP found.")
        return

    for entry in conn.entries:
        print(f"Object:         {get_attr(entry, 'distinguishedName')}")
        print(f"Applied Policy: {get_attr(entry, 'msDS-PSOApplied')}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Dump Fine Grained Password Policies via LDAP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -l dc01.corp.local -d corp.local -u jdoe -p Password123
  %(prog)s -l 10.10.10.1 -d corp.local -u jdoe -H :aabbccddeeff00112233445566778899
  %(prog)s -l dc01.corp.local -d corp.local --kerberos --use-ldaps
        """,
    )
    parser.add_argument('-l', '--ldapserver', help='LDAP server (hostname or IP)', required=True)
    parser.add_argument('-d', '--domain',     help='AD domain (e.g. corp.local)', required=True)
    parser.add_argument('-u', '--username',   help='LDAP username')
    parser.add_argument('-p', '--password',   help='LDAP password')
    parser.add_argument('-H', '--hashes',     help='NTLM hashes (lmhash:nthash or :nthash)')
    parser.add_argument('--use-ldaps',        help='Use LDAPS (SSL/TLS)', action='store_true')
    parser.add_argument('--kerberos',         help='Use Kerberos (GSSAPI)', action='store_true')
    parser.add_argument('--port',             help='Custom port (default: 389 or 636)', type=int)

    args = parser.parse_args()

    try:
        conn = connect(args)
    except (ValueError, ConnectionError) as e:
        err(f"[-] {e}")
        sys.exit(1)

    enumerate_fgpp(conn, args.domain)
    enumerate_applied_objects(conn, args.domain)


if __name__ == "__main__":
    main()
