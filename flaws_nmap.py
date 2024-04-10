############################
if __name__ != 'flaws_nmap':
    exit('[!] Error: Missing FLAWS context! Please do not call this file directly.')
############################

#############
import nmap
import time
import re
import os

from flaws_utils import get_target_host, get_target_port_or_none, get_targets, get_sub_domains
from flaws_utils import is_valid_host, is_valid_port, random_value, delete_empty_target
from flaws_utils import load_list, load_database, update_database, green, cyan, yellow, red
#############

nm = None

privileged  = True

dns_servers = {
    "1.0.0.1": 0, # Cloudflare
    "1.1.1.1": 0, # Cloudflare
    "8.8.4.4": 0, # Google
    "8.8.8.8": 0, # Google
    "208.67.220.220": 0, # OpenDNS
    "208.67.222.222": 0 # OpenDNS
}

def get_pattern( item ):
    return item.replace('-', '\-').replace('.', '\.').replace('*', '([a-z0-9\-\.\*]*)')

def nmap_init():
    try:
        global nm
        nm = nmap.PortScanner()
        return True
    except Exception:
        print( red('[!] Error: Failed to initialize nmap scanner!') )
        return False

def check_connectivity():

    tries = 3
    while tries:
        tries -= 1

        server = min(dns_servers, key=dns_servers.get)

        # -n:  Never do DNS resolution
        # -sn: Ping Scan - disable port scan
        result = nm.scan( server, arguments='-n -sn' )
        dns_servers[ server ] += 1

        try:
            if result['nmap']['scanstats']['uphosts'] == '1':
                return True
        except Exception:
            pass

        if tries:
            print( yellow('[!] Warning: Unable to resolve the DNS Servers! Retrying after 5 seconds...') )
            time.sleep(5)
        else:
            print( red('[!] Error: Failed to resolve DNS servers! Check your connection.') )
            return False

def count_dns_servers_requests():
    total = 0
    for s in dns_servers:
        total += dns_servers[s]
    return total

def reset_dns_servers_counts():
    for s in dns_servers:
        dns_servers[s] = 0

def ports_scanner( host, target_port, check_connection, delay, is_force, is_validate, exclude_list, save_results ):

    global privileged

    print( cyan('[~] Scanning ports for target "' + host + '"...') )

    if not nm and not nmap_init():
        return

    host_to_scan = host.replace( '*', random_value(10) )

    if not is_force or is_validate or save_results:
        database = load_database( host )

    ports = [] if (is_validate and not is_force) else load_list('ports')
    ports_removed = False

    if is_validate:
        for port in database['ports']['found'] + database['ports']['not_found']:
            if port not in ports:
                ports.append(port)
    elif not is_force:
        for port in database['ports']['found'] + database['ports']['not_found']:
            if port in ports:
                ports.remove(port)
                ports_removed = True

            if target_port == port:
                target_port = None

    if (not is_validate or is_force) and target_port and target_port not in ports:
        if not exclude_list or str(target_port) not in exclude_list:
            ports.append( target_port )
            print( cyan('[~] Port "' + str(target_port) + '" added to the ports list.') )

    if ports:
        if exclude_list:
            for i in exclude_list:
                if is_valid_port(i) and int(i) in ports:
                    ports.remove( int(i) )

            if not ports:
                print( red('[!] Error: No ports left to scan! Try to remove -E/--exclude option.') )
                return
    else:
        if is_validate:
            if is_force:
                print( red('[!] Error: No ports to scan/validate! Check your lists.') )
            else:
                print( red('[!] Error: No ports to validate! Try normal scan first.') )
        elif is_force or not ports_removed:
            print( red('[!] Error: No ports to scan! Check your lists.') )
        else:
            print( yellow('[!] Warning: Ports already scanned, Use -F/--force option to force scan.') )

        return

    first_req   = True
    total_ports = len(ports)
    found_ports = 0

    for port in ports:

        if first_req:
            first_req = False
        elif delay:
            time.sleep(delay)

        uphosts = '0'
        state = ''
        append_list = 'not_found'
        remove_list = 'found'
        tries = 3

        while uphosts != '1' and tries:
            tries -= 1

            if check_connection and not check_connectivity():
                return

            if privileged:
                try:
                    # -sY: SCTP INIT scan
                    # -sS: TCP SYN scan
                    # -sU: UDP scan
                    # -sV: Determine service/version info [ --version-light ]
                    # -n:  Never do DNS resolution
                    result = nm.scan( host_to_scan, arguments='-sY -sS -sU -sV --version-light -n -p ' + str(port) )
                except Exception:
                    privileged = False
                    print( cyan('[~] Not a privileged user! Running the default TCP scan...') )

            if not privileged:
                # -sT: TCP connect scan (default TCP scan type)
                # -n:  Never do DNS resolution
                result = nm.scan( host_to_scan, arguments='-sT -n -p ' + str(port) )

            try:
                uphosts = result['nmap']['scanstats']['uphosts']

                scan_values = list( result['scan'].values() )[0]
                for protocol in scan_values:
                    if protocol in [ 'tcp', 'udp', 'sctp' ]:
                        if scan_values[ protocol ][ port ]['state'] == 'open':
                            state = 'open'
                            break
            except Exception:
                pass

            if not tries:
                print( red('[!] Error: Failed to resolve the target! Maybe host is down.') )
                return
            elif uphosts != '1':
                print( yellow('[!] Warning: Unable to resolve the target! Retrying after 5 seconds...') )
                time.sleep(5)

        if state == 'open':
            found_ports += 1
            print( green('[+] Port "' + str(port) + '" is open') )

            append_list = 'found'
            remove_list = 'not_found'

        if save_results:
            if port not in database['ports'][ append_list ]:
                database['ports'][ append_list ].append(port)
            while port in database['ports'][ remove_list ]:
                # Clean old results and duplicates
                database['ports'][ remove_list ].remove(port)
            update_database( host, database )

    dns_requests = count_dns_servers_requests()
    reset_dns_servers_counts()
    scan_stats = '[~] Finished! Total ports [' + str(found_ports) + '/' + str(total_ports) + ']'
    if check_connection:
        scan_stats += ', Total DNS servers pings "' + str(dns_requests) + '"'
    print( cyan( scan_stats + '.' ) )

    if save_results:
        database['ports']['last_scan'] = time.strftime("%Y/%m/%d %I:%M:%S %p")
        update_database( host, database )

def ports_checker( target, check_connection, delay, is_force, is_validate, exclude_list, recursive, save_results ):

    host = get_target_host( target )
    target_port = get_target_port_or_none( target )

    ports_scanner( host, target_port, check_connection, delay, is_force, is_validate, exclude_list, save_results )

    if nm and recursive:
        for s in get_sub_domains( host ):
            if is_valid_host( s ):
                ports_scanner( s, target_port, check_connection, delay, is_force, is_validate, exclude_list, save_results )

def subdomains_scanner( host, check_connection, delay, is_force, is_validate, exclude_list, save_results ):

    print( cyan('[~] Scanning subdomains for target "' + host + '"...') )

    if not nm and not nmap_init():
        return

    if not is_valid_host( host ):
        # Probably an IP
        print( red('[!] Error: Cannot check for subdomains! Target is IP!') )
        return
    elif host.startswith('*'):
        print( red('[!] Error: Cannot check for subdomains! Target is wildcard!') )
        return

    if not is_force or is_validate or save_results:
        database = load_database( host )

        if not is_force or is_validate:
            found_subdomains = list(map( lambda s: s[ : - (len(host)+1) ], get_sub_domains( host ) ))

            if not is_validate and '*' in found_subdomains:
                print( yellow('[!] Warning: Target has wildcard subdomain, You can use "-V" or "-F" option.') )
                return

    wordlist = [] if (is_validate and not is_force) else load_list('subdomains')
    words_removed = False

    if is_validate:
        for subdomain in database['subdomains']['not_found'] + found_subdomains:
            if subdomain not in wordlist:
                wordlist.append(subdomain)
    elif not is_force:
        for subdomain in database['subdomains']['not_found'] + found_subdomains:
            if '*' in subdomain:
                wordlist_length = len(wordlist)
                pattern = get_pattern( subdomain )
                wordlist = [ _ for _ in wordlist if not re.compile(pattern).fullmatch(_) ]

                if wordlist_length != len(wordlist):
                    words_removed = True

            elif subdomain in wordlist:
                wordlist.remove(subdomain)
                words_removed = True

    if wordlist:
        new_subdomains = []
        for subdomain in wordlist:
            if '.' in subdomain:
                for part in subdomain.split('.'):
                    if part != '*' and part not in wordlist and part not in new_subdomains:
                        new_subdomains.append(part)

        if exclude_list:
            for item in exclude_list:
                if re.compile('[a-z0-9\-\.\*]+').fullmatch(item):
                    if item.endswith( '.' + host ):
                        item = item[ : -(len(host)+1) ]

                    if item:
                        pattern = get_pattern( item )
                        wordlist = [ _ for _ in wordlist if not re.compile(pattern).fullmatch(_) ]
                        new_subdomains = [ _ for _ in new_subdomains if not re.compile(pattern).fullmatch(_) ]

        if new_subdomains:
            for s in new_subdomains:
                wordlist.append(s)
            print( cyan('[~] New subdomains added to the list: ' + str(new_subdomains) + '.') )

        if not wordlist:
            print( red('[!] Error: No subdomains left to scan! Try to remove -E/--exclude option.') )
            return
    else:
        if is_validate:
            if is_force:
                print( red('[!] Error: No subdomains to scan/validate! Check your lists.') )
            else:
                print( red('[!] Error: No subdomains to validate! Try normal scan first.') )
        elif is_force or not words_removed:
            print( red('[!] Error: No subdomains to scan! Check your lists.') )
        else:
            print( yellow('[!] Warning: Subdomains already scanned, Use -F/--force option to force scan.') )

        return

    found_wildcards  = []
    found_subdomains = []
    total_subdomains = len(wordlist)

    first_req = True

    for subdomain in wordlist:

        skip = False
        for i in found_wildcards:
            pattern = get_pattern( i )
            if re.compile(pattern).fullmatch(subdomain):
                skip = True
                break
        if skip:
            continue

        if first_req:
            first_req = False
        elif delay:
            time.sleep(delay)

        if check_connection and not check_connectivity():
            return

        uphosts = '0'

        # -n:  Never do DNS resolution
        # -sn: Ping Scan - disable port scan
        result = nm.scan( subdomain.replace( '*', random_value(10) ) + '.' + host, arguments='-n -sn' )

        try:
            uphosts = result['nmap']['scanstats']['uphosts']
        except Exception:
            pass

        if uphosts == '1':

            reversed_parts = ''
            for i in subdomain.split('.')[::-1]:
                reversed_parts = (i + '.' + reversed_parts) if reversed_parts else i
                maybe_dot = '.' if reversed_parts.count('.') else ''
                random_subdomain = random_value(10) + maybe_dot + '.'.join( reversed_parts.split('.')[1:] )

                confirm = nm.scan( random_subdomain + '.' + host, arguments='-n -sn' )
                try:
                    if confirm['nmap']['scanstats']['uphosts'] == '1':
                        subdomain = '*' + maybe_dot + '.'.join( reversed_parts.split('.')[1:] )
                        found_wildcards.append( subdomain )
                        break
                except Exception:
                    pass

            target = subdomain + '.' + host
            print( green('[+] Subdomain "' + target + '" is up') )
            found_subdomains.append(target)

            if save_results:
                if not os.path.isfile(os.path.join( 'targets', target.replace('*', 'WILDCARD') + '.json' )):
                    update_database( target, load_database( target ) )

                if '*' in subdomain:
                    targets = get_targets()
                    for t in targets:
                        pattern = get_pattern(target)
                        if re.compile(pattern).fullmatch(t) and t != target:
                            delete_empty_target(t)

                while subdomain in database['subdomains']['not_found']:
                    database['subdomains']['not_found'].remove(subdomain)
                update_database( host, database )
        else:
            if save_results:
                delete_empty_target( subdomain + '.' + host )

                # Some subdomains are up and their parents are not, Skip pattern deletions.

                if '*' not in subdomain:
                    if subdomain not in database['subdomains']['not_found']:
                        database['subdomains']['not_found'].append(subdomain)
                        update_database( host, database )

        if save_results:
            subdomain_parts = subdomain.split('.')[:-1]
            inner_subdomain = ''
            for part in subdomain_parts:
                inner_subdomain += ('.' + part) if inner_subdomain else part
                inner_target = subdomain[ (len(inner_subdomain)+1) : ] + '.' + host
                if os.path.isfile(os.path.join( 'targets', inner_target.replace('*', 'WILDCARD') + '.json' )):
                    inner_db = load_database( inner_target )
                    if uphosts == '1':
                        while inner_subdomain in inner_db['subdomains']['not_found']:
                            inner_db['subdomains']['not_found'].remove(inner_subdomain)
                    elif inner_subdomain not in inner_db['subdomains']['not_found']:
                        inner_db['subdomains']['not_found'].append(inner_subdomain)
                    update_database( inner_target, inner_db )
                    # Free the memory
                    inner_db = None

    dns_requests = count_dns_servers_requests()
    reset_dns_servers_counts()
    scan_stats = '[~] Finished! Total subdomains [' + str(len(found_subdomains)) + '/' + str(total_subdomains) + ']'
    if check_connection:
        scan_stats += ', Total DNS servers pings "' + str(dns_requests) + '"'
    print( cyan( scan_stats + '.' ) )

    if save_results:
        database['subdomains']['last_scan'] = time.strftime("%Y/%m/%d %I:%M:%S %p")
        update_database( host, database )
    
    return found_subdomains

def subdomains_checker( target, check_connection, delay, is_force, is_validate, exclude_list, recursive, save_results ):

    host = get_target_host( target )
    found = subdomains_scanner( host, check_connection, delay, is_force, is_validate, exclude_list, save_results )

    if nm and recursive:
        subdomains = get_sub_domains( host )

        if found:
            for s in found:
                if s not in subdomains:
                    subdomains.append(s)

        scanned = []
        exclude = []

        if exclude_list:
            for item in exclude_list:
                if re.compile('[a-z0-9\-\.\*]+').fullmatch(item):
                    if not item.endswith( '.' + host ):
                        item += '.' + host
                    exclude.append(item)

        def recursive_subdomains( targets ):
            targets.sort()

            for t in targets:
                if '*' in t and t not in exclude:
                    exclude.append(t)

            for t in targets:
                skip = False

                for i in exclude:
                    pattern = get_pattern( i )
                    if re.compile(pattern).fullmatch(t):
                        skip = True
                        break

                if t in scanned or skip:
                    continue

                found = subdomains_scanner( t, check_connection, delay, is_force, is_validate, exclude_list, save_results )

                scanned.append(t)
                if found:
                    recursive_subdomains(found)

        recursive_subdomains( subdomains )