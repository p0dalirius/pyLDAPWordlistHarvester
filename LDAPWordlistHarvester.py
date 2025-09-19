#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : LDAPWordlistHarvester.py
# Author             : Podalirius (@podalirius_)
# Date created       : 22 Sep 2023


import argparse
from sectools.windows.ldap.ldap import raw_ldap_query, init_ldap_session
from sectools.windows.crypto import parse_lm_nt_hashes
import os
import sys


VERSION = "1.2"


def get_domain_from_distinguished_name(distinguishedName):
    domain = None
    if "dc=" in distinguishedName.lower():
        distinguishedName = distinguishedName.lower().split(',')[::-1]

        while distinguishedName[0].startswith("dc="):
            if domain is None:
                domain = distinguishedName[0].split('=',1)[1]
            else:
                domain = distinguishedName[0].split('=', 1)[1] + "." + domain
            distinguishedName = distinguishedName[1:]

    return domain


def get_ou_path_from_distinguished_name(distinguishedName):
    ou_path = None
    if "ou=" in distinguishedName.lower():
        distinguishedName = distinguishedName.lower().split(',')[::-1]

        # Skip domain
        while distinguishedName[0].startswith("dc="):
            distinguishedName = distinguishedName[1:]

        while distinguishedName[0].startswith("ou="):
            if ou_path is None:
                ou_path = distinguishedName[0].split('=',1)[1]
            else:
                ou_path = ou_path + " --> " + distinguishedName[0].split('=',1)[1]
            distinguishedName = distinguishedName[1:]

        return ou_path
    else:
        return ou_path


def parseArgs():
    print("LDAPWordlistHarvester.py v%s - by Remi GASCOU (Podalirius)\n" % VERSION)

    parser = argparse.ArgumentParser(description="")

    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("-o", "--outputfile", default="wordlist.txt", help="Path to output file of wordlist.")

    authconn = parser.add_argument_group('Authentication & connection')
    authconn.add_argument("--dc-ip", required=True, action="store", metavar="ip address", help="IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter")
    authconn.add_argument('--kdcHost', dest="kdcHost", action='store', metavar="FQDN KDC", help='FQDN of KDC for Kerberos.')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default="", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", default="", help="user to authenticate with")
    authconn.add_argument("--ldaps", dest="use_ldaps", action="store_true", default=False, help="Use LDAPS instead of LDAP")

    secret = parser.add_argument_group("Credentials")
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", default=False, action="store_true", help="Don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", default=None, help="Password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", default=None, help="NT/LM hashes, format is LMhash:NThash")
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.auth_password is None and options.no_pass == False and options.auth_hashes is None and options.auth_key is None:
        print("[+] No password of hashes provided and --no-pass is '%s'" % options.no_pass)
        from getpass import getpass
        if options.auth_domain is not None:
            options.auth_password = getpass("  | Provide a password for '%s\\%s':" % (options.auth_domain, options.auth_username))
        else:
            options.auth_password = getpass("  | Provide a password for '%s':" % options.auth_username)

    return options


if __name__ == '__main__':
    options = parseArgs()

    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes
        auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(options.auth_hashes)
    else:
        auth_lm_hash, auth_nt_hash = None, None

    if options.auth_key is not None:
        options.use_kerberos = True

    if options.use_kerberos is True and options.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()

    wordlist = []

    print("[>] Connecting to remote LDAP host '%s' ... " % options.dc_ip, end="", flush=True)
    ldap_server, ldap_session = init_ldap_session(
        auth_domain=options.auth_domain,
        auth_username=options.auth_username,
        auth_password=options.auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        auth_key=options.auth_key,
        use_kerberos=options.use_kerberos,
        kdcHost=options.kdcHost,
        use_ldaps=options.use_ldaps,
        auth_dc_ip=options.dc_ip
    )
    configurationNamingContext = ldap_server.info.other["configurationNamingContext"]
    defaultNamingContext = ldap_server.info.other["defaultNamingContext"]
    print("done.")


    # Extracting AD sites
    print("[>] Extracting AD Sites from LDAP ... ", end="", flush=True)
    ldap_results = raw_ldap_query(
        auth_domain=options.auth_domain, auth_dc_ip=options.dc_ip, auth_username=options.auth_username, auth_password=options.auth_password, auth_hashes=options.auth_hashes, auth_key=options.auth_key,
        searchbase=configurationNamingContext, use_ldaps=options.use_ldaps, use_kerberos=options.use_kerberos, kdcHost=options.kdcHost,
        query="(objectClass=site)", attributes=["name", "description"]
    )
    added_words = []
    for dn, data in ldap_results.items():
        added_words += ' '.join(data["description"]).split(' ')
        if type(data["name"]) == list:
            added_words += ' '.join([e for e in data["name"] if len(e) != 0]).split(' ')
        else:
            added_words += data["name"].split(' ')
    added_words = list(set(added_words))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))


    # Extracting user and computer
    print("[>] Extracting user and computer names from LDAP ... ", end="", flush=True)
    ldap_results = raw_ldap_query(
        auth_domain=options.auth_domain, auth_dc_ip=options.dc_ip, auth_username=options.auth_username, auth_password=options.auth_password, auth_hashes=options.auth_hashes, auth_key=options.auth_key,
        searchbase=defaultNamingContext, use_ldaps=options.use_ldaps, use_kerberos=options.use_kerberos, kdcHost=options.kdcHost,
        query="(|(objectClass=person)(objectClass=user)(objectClass=computer))", attributes=["name", "sAMAccountName"]
    )
    added_words = []
    for dn, data in ldap_results.items():
        if len(data["sAMAccountName"]) != 0:
            if type(data["sAMAccountName"]) == list:
                added_words += ' '.join([e for e in data["sAMAccountName"] if len(e) != 0]).split(' ')
            else:
                added_words.append(data["sAMAccountName"])
        if len(data["sAMAccountName"]) != 0:
            if type(data["sAMAccountName"]) == list:
                added_words += ' '.join([e for e in data["sAMAccountName"] if len(e) != 0]).split(' ')
            else:
                added_words.append(data["sAMAccountName"])
    added_words = list(set(added_words))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))


    # Extracting descriptions
    print("[>] Extracting descriptions of all LDAP objects ... ", end="", flush=True)
    ldap_results = raw_ldap_query(
        auth_domain=options.auth_domain, auth_dc_ip=options.dc_ip, auth_username=options.auth_username, auth_password=options.auth_password, auth_hashes=options.auth_hashes, auth_key=options.auth_key,
        searchbase=defaultNamingContext, use_ldaps=options.use_ldaps, use_kerberos=options.use_kerberos, kdcHost=options.kdcHost,
        query="(description=*)", attributes=["description"]
    )
    added_words = []
    for dn, data in ldap_results.items():
        added_words += ' '.join(data["description"]).split(' ')
    added_words = list(set(added_words))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))


    # Extracting group names
    print("[>] Extracting group names of all LDAP objects ... ", end="", flush=True)
    ldap_results = raw_ldap_query(
        auth_domain=options.auth_domain, auth_dc_ip=options.dc_ip, auth_username=options.auth_username, auth_password=options.auth_password, auth_hashes=options.auth_hashes, auth_key=options.auth_key,
        searchbase=defaultNamingContext, use_ldaps=options.use_ldaps, use_kerberos=options.use_kerberos, kdcHost=options.kdcHost,
        query="(objectCategory=group)", attributes=["name"]
    )
    added_words = []
    for dn, data in ldap_results.items():
        if type(data["name"]) == list:
            added_words += ' '.join([e for e in data["name"] if len(e) != 0]).split(' ')
            added_words += [e for e in data["name"] if len(e) != 0]
        else:
            added_words.append(data["name"])
            added_words += ' '.join(data["name"]).split(' ')
    added_words = list(set(added_words))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))


    # Extracting organizationalUnit
    print("[>] Extracting organizationalUnit names ... ", end="", flush=True)
    ldap_results = raw_ldap_query(
        auth_domain=options.auth_domain, auth_dc_ip=options.dc_ip, auth_username=options.auth_username, auth_password=options.auth_password, auth_hashes=options.auth_hashes, auth_key=options.auth_key,
        searchbase=defaultNamingContext, use_ldaps=options.use_ldaps, use_kerberos=options.use_kerberos, kdcHost=options.kdcHost,
        query="(objectCategory=organizationalUnit)", attributes=["name"]
    )
    added_words = []
    for dn, data in ldap_results.items():
        if type(data["name"]) == list:
            added_words += ' '.join([e for e in data["name"] if len(e) != 0]).split(' ')
            added_words += [e for e in data["name"] if len(e) != 0]
        else:
            added_words.append(data["name"])
            added_words += ' '.join(data["name"]).split(' ')
    added_words = list(set(added_words))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))


    # Extracting servicePrincipalName
    print("[>] Extracting servicePrincipalName of all LDAP objects ... ", end="", flush=True)
    ldap_results = raw_ldap_query(
        auth_domain=options.auth_domain, auth_dc_ip=options.dc_ip, auth_username=options.auth_username, auth_password=options.auth_password, auth_hashes=options.auth_hashes, auth_key=options.auth_key,
        searchbase=defaultNamingContext, use_ldaps=options.use_ldaps, use_kerberos=options.use_kerberos, kdcHost=options.kdcHost,
        query="(servicePrincipalName=*)", attributes=["servicePrincipalName"]
    )
    added_words = []
    for dn, data in ldap_results.items():
        for spn in data["servicePrincipalName"]:
            added_words.append(spn)
            added_words += spn.split('/')
            added_words += spn.replace('.','/').split('/')
    added_words = list(set(added_words))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))


    # Extracting trustedDomains
    print("[>] Extracting trustedDomains from LDAP ... ", end="", flush=True)
    ldap_results = raw_ldap_query(
        auth_domain=options.auth_domain, auth_dc_ip=options.dc_ip, auth_username=options.auth_username, auth_password=options.auth_password, auth_hashes=options.auth_hashes, auth_key=options.auth_key,
        searchbase=defaultNamingContext, use_ldaps=options.use_ldaps, use_kerberos=options.use_kerberos, kdcHost=options.kdcHost,
        query="(objectClass=trustedDomain)", attributes=["name"]
    )
    added_words = []
    for dn, data in ldap_results.items():
        if type(data["name"]) == list:
            added_words += ' '.join([e for e in data["name"] if len(e) != 0]).split('.')
            added_words += [e for e in data["name"] if len(e) != 0]
        else:
            added_words.append(data["name"])
            added_words += data["name"].split('.')
    added_words = list(set(added_words))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))


    # Exporting output
    print()
    print("[+] Writing %d words to '%s' ... " % (len(wordlist), options.outputfile))
    basepath = os.path.dirname(options.outputfile)
    filename = os.path.basename(options.outputfile)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename
    f = open(path_to_file, "w")
    for word in wordlist:
        f.write(word+"\n")
    f.close()
    print("[+] Bye Bye!")
