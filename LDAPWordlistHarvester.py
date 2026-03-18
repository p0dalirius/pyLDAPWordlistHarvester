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

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False


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


def neo4j_query(driver, query):
    """Execute a Neo4j query and return results"""
    results = []
    with driver.session() as session:
        result = session.run(query)
        for record in result:
            results.append(dict(record))
    return results


def extract_from_neo4j(driver):
    """
    Extract wordlist data from a Neo4j/BloodHound database.

    This function queries the Neo4j database for nodes labeled as `User` or `Computer`.
    It expects these nodes to have the following properties:
        - `name`: The display name of the user or computer (string).
        - `samaccountname`: The SAM account name (string).
        - `description`: A description field (string, may be empty).

    The function extracts words from these properties to build a wordlist.
    It assumes that the BloodHound database uses the default schema as produced by BloodHound
    (tested with BloodHound v4.x and above), and that the relevant properties exist on the nodes.

    Node labels expected:
        - User
        - Computer

    Properties expected on these nodes:
        - name
        - samaccountname
        - description

    If the BloodHound schema or property names differ, this function may need to be updated.

    Args:
        driver: A Neo4j driver instance (from neo4j.GraphDatabase).

    Returns:
        list: A list of unique words extracted from the specified properties.
    """
    wordlist = []
    
    # Extracting user and computer names
    print("[>] Extracting user and computer names from Neo4j ... ", end="", flush=True)
    query = """
    MATCH (n)
    WHERE n:User OR n:Computer
    RETURN n.name as name, n.samaccountname as samaccountname, n.description as description
    """
    results = neo4j_query(driver, query)
    added_words = []
    for record in results:
        if record.get('name'):
        if record.get('name') and isinstance(record['name'], str):
            added_words.append(record['name'])
            added_words += record['name'].split(' ')
        if record.get('samaccountname'):
            added_words.append(record['samaccountname'])
        if record.get('description') and isinstance(record['description'], str):
            if isinstance(record['description'], str):
                added_words += record['description'].split(' ')
    added_words = list(set([w for w in added_words if w]))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))
    
    # Extracting group names
    print("[>] Extracting group names from Neo4j ... ", end="", flush=True)
    query = """
    MATCH (g:Group)
    RETURN g.name as name, g.description as description
    """
    results = neo4j_query(driver, query)
    added_words = []
    for record in results:
        if record.get('name'):
            added_words.append(record['name'])
            added_words += record['name'].split(' ')
        if record.get('description'):
            added_words += record['description'].split(' ')
    added_words = list(set([w for w in added_words if w]))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))
    
    # Extracting organizational units
    print("[>] Extracting OU names from Neo4j ... ", end="", flush=True)
    query = """
    MATCH (ou:OU)
    RETURN ou.name as name, ou.description as description
    """
    results = neo4j_query(driver, query)
    added_words = []
    for record in results:
        if record.get('name'):
            added_words.append(record['name'])
            added_words += record['name'].split(' ')
        if record.get('description'):
            added_words += record['description'].split(' ')
    added_words = list(set([w for w in added_words if w]))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))
    
    # Extracting domains
    print("[>] Extracting domain names from Neo4j ... ", end="", flush=True)
    query = """
    MATCH (d:Domain)
    RETURN d.name as name, d.description as description
    """
    results = neo4j_query(driver, query)
    added_words = []
    for record in results:
        if record.get('name'):
            added_words.append(record['name'])
            if isinstance(record['name'], str):
                added_words += record['name'].split('.')
        if record.get('description'):
            added_words += record['description'].split(' ')
    added_words = list(set([w for w in added_words if w]))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))
    
    # Extracting GPO names
    print("[>] Extracting GPO names from Neo4j ... ", end="", flush=True)
    query = """
    MATCH (g:GPO)
    RETURN g.name as name, g.displayname as displayname, g.description as description
    """
    results = neo4j_query(driver, query)
    added_words = []
    for record in results:
        if record.get('name') and isinstance(record['name'], str):
            added_words.append(record['name'])
            added_words += record['name'].split(' ')
        if record.get('displayname') and isinstance(record['displayname'], str):
            added_words.append(record['displayname'])
            added_words += record['displayname'].split(' ')
        if record.get('description') and isinstance(record['description'], str):
            added_words += record['description'].split(' ')
    added_words = list(set([w for w in added_words if w]))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))
    
    # Extracting service principal names
    print("[>] Extracting SPNs from Neo4j ... ", end="", flush=True)
    query = """
    MATCH (n)
    WHERE n.serviceprincipalnames IS NOT NULL
    RETURN n.serviceprincipalnames as spns
    """
    results = neo4j_query(driver, query)
    added_words = []
    for record in results:
        if record.get('spns'):
            spns = record['spns']
            if isinstance(spns, list):
                for spn in spns:
                    if spn:
                        added_words.append(spn)
                        added_words += spn.split('/')
                        added_words += spn.replace('.', '/').split('/')
            else:
                if spns:
                    added_words.append(spns)
                    added_words += spns.split('/')
                    added_words += spns.replace('.', '/').split('/')
    added_words = list(set([w for w in added_words if w]))
    print("found %d words" % (len(added_words)), flush=True)
    len_before = len(wordlist)
    wordlist = list(set(wordlist + added_words))
    len_after = len(wordlist)
    print(" └──[+] Added %d unique words to wordlist." % (len_after - len_before))
    
    return wordlist


def parseArgs():
    print("LDAPWordlistHarvester.py v%s - by Remi GASCOU (Podalirius)\n" % VERSION)

    parser = argparse.ArgumentParser(description="")

    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("-o", "--outputfile", default="wordlist.txt", help="Path to output file of wordlist.")

    # Source selection
    source = parser.add_argument_group('Data source')
    source.add_argument("--use-neo4j", dest="use_neo4j", action="store_true", default=False, help="Use Neo4j/BloodHound database instead of LDAP (offline mode)")
    source.add_argument("--neo4j-uri", dest="neo4j_uri", action="store", default="bolt://localhost:7687", help="Neo4j connection URI (default: bolt://localhost:7687)")
    source.add_argument("--neo4j-user", dest="neo4j_user", action="store", default="neo4j", help="Neo4j username (default: neo4j)")
    source.add_argument("--neo4j-pass", dest="neo4j_pass", action="store", default=None, help="Neo4j password")

    authconn = parser.add_argument_group('Authentication & connection (LDAP mode)')
    authconn.add_argument("--dc-ip", required=False, action="store", metavar="ip address", help="IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter")
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

    # Validate Neo4j availability
    if options.use_neo4j and not NEO4J_AVAILABLE:
        print("[!] Neo4j library is not available. Please install it: pip install neo4j")
        sys.exit(1)

    # Validate options based on mode
    if options.use_neo4j:
        if options.neo4j_pass is None:
            from getpass import getpass
            options.neo4j_pass = getpass("  | Provide Neo4j password for '%s':" % options.neo4j_user)
    else:
        # LDAP mode validation
        if options.dc_ip is None:
            print("[!] --dc-ip is required for LDAP mode")
            sys.exit(1)
        
        if options.auth_password is None and options.no_pass == False and options.auth_hashes is None and options.auth_key is None:
            print("[+] No password or hashes provided and --no-pass is '%s'" % options.no_pass)
            from getpass import getpass
            if options.auth_domain is not None:
                options.auth_password = getpass("  | Provide a password for '%s\\%s':" % (options.auth_domain, options.auth_username))
            else:
                options.auth_password = getpass("  | Provide a password for '%s':" % options.auth_username)

    return options


if __name__ == '__main__':
    options = parseArgs()

    wordlist = []

    if options.use_neo4j:
        # Neo4j mode
        print("[>] Connecting to Neo4j database at '%s' ... " % options.neo4j_uri, end="", flush=True)
        try:
            driver = GraphDatabase.driver(options.neo4j_uri, auth=(options.neo4j_user, options.neo4j_pass))
            # Test connection
            driver.verify_connectivity()
            print("done.")
            print()
        except Exception as e:
            print("failed!")
            print("[!] Error connecting to Neo4j: %s" % str(e))
            sys.exit(1)

        try:
            # Extract data from Neo4j
            wordlist = extract_from_neo4j(driver)
        except Exception as e:
            print("[!] Error during Neo4j operation: %s" % str(e))
            driver.close()
            sys.exit(1)
        driver.close()
    else:
        # LDAP mode
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
        print()

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
