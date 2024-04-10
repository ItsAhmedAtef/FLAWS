# FLAWS listing targets segments

############################
if __name__ != 'flaws_ls':
    exit('[!] Error: Missing FLAWS context! Please do not call this file directly.')
############################

#########
import os

from flaws_fuzzer import colored_codes
from flaws_utils  import get_targets, get_parent_domain, get_sub_domains
from flaws_utils  import get_target_host, load_database, green, cyan, red, yellow
#########

BDLH  = '\u2500' # Box Drawings Light Horizontal
BDLV  = '\u2502' # Box Drawings Light Vertical
BDLUR = '\u2514' # Box Drawings Light Up and Right
BDLVR = '\u251C' # Box Drawings Light Vertical and Right

def list_targets( spaces='', targets=None, connected_branch=False ):
    if targets is None:
        targets = get_targets()

        if not targets:
            exit( red('[!] Error: No targets found!') )

        print( green('Available targets:') )

    filtered = list(filter( lambda t: not get_parent_domain(t, targets), targets ))
    filtered_length = len(filtered)

    for i in range( filtered_length ):
        target_subdomains = get_sub_domains(filtered[i], targets)

        branch = BDLV + ' ' if connected_branch else '  '
        leaf   = BDLVR      if connected_branch else BDLUR
        if filtered_length != (i+1):
            leaf = BDLVR
            if target_subdomains:
                branch = BDLV + ' '

        print( green(spaces + leaf + BDLH + '[+] ') + filtered[i] )
        list_targets( spaces + branch, target_subdomains )

def list_endpoints( endpoints_db={} ):
    endpoints = {}
    last_scan = endpoints_db['last_scan']

    endpoints_db.pop('last_scan', None)
    for p in endpoints_db:
        for endpoint in endpoints_db[p]:
            status_code = endpoints_db[p][endpoint]
            if status_code != 404:

                if p not in endpoints:
                    endpoints[ p ] = {}
                endpoints[ p ][ endpoint ] = status_code

    i = len(endpoints)
    if endpoints:
        print( green('[+] HTTP/S Endpoints: ') )
        for p in sorted(endpoints, key=lambda e: int(e)):
            i -= 1
            connector = (BDLVR if last_scan or i else BDLUR) + BDLH
            print( green( connector + '[+] Port [' + p + ']: ') )

            for endpoint in sorted(endpoints[p]):
                connector = green(BDLV) + '  ' if last_scan or i else '  '

                e = endpoint[:-1] if endpoint.endswith('/') else endpoint
                while '/'.join(e.split('/')[:-1]):
                    e = '/'.join(e.split('/')[:-1])
                    if (e in endpoints[p]) or (e+'/' in endpoints[p]):
                        connector += '  '

                status_code = endpoints[p][ endpoint ]
                print( connector + colored_codes(status_code, '/' + endpoint) )

    else:
        print( red('[!] HTTP/S Endpoints: ') + 'Nothing found!' )

    if last_scan:
        print( cyan(BDLUR + BDLH + '[~] Last scan: ') + last_scan )

def list_target( target ):
    host = get_target_host( target )

    if os.path.isfile( os.path.join( 'targets', host.replace('*', 'WILDCARD') + '.json' ) ):
        database = load_database( host )

        print( cyan('[~] Host: ') + host )

        ##############################
        ports = database['ports']['found']
        ports.sort()
        if ports:
            print( green('[+] Open ports [' + str(len(ports)) + ']: ') + green(', ').join(map(str, ports)) )
        else:
            print( red('[!] Open ports: ') + 'Nothing found!' )

        last_scan = database['ports']['last_scan']
        if last_scan:
            print( cyan(BDLUR + BDLH + '[~] Last scan: ') + last_scan )
        ##############################

        ##############################
        subdomains = get_sub_domains( host )
        last_scan  = database['subdomains']['last_scan']
        if subdomains:
            print( green('[+] Subdomains [' + str(len(subdomains)) + ']: ') )
            list_targets( targets=subdomains, connected_branch=last_scan )

        else:
            print( red('[!] Subdomains: ') + 'Nothing found!' )

        if last_scan:
            print( cyan(BDLUR + BDLH + '[~] Last scan: ') + last_scan )
        ##############################

        ##############################
        list_endpoints( database['endpoints'] )
        ##############################

    else:
        print( red('[!] Error: Target database not found!') )