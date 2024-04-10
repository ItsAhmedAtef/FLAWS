############################
if __name__ != 'flaws_fuzzer':
    exit('[!] Error: Missing FLAWS context! Please do not call this file directly.')
############################

#############
import re
import time
import random
import requests

from flaws_utils import get_target_host, get_target_port_or_none, is_valid_endpoint
from flaws_utils import load_database, load_list, update_database, cyan, yellow, red, green
#############

timeout = 20
max_recursive = 5

redirections_codes = [301, 302]
# 301 => Moved Permanently
# 302 => Moved Temporarily

ok_status = 0
total_status = 0

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36', # Chrome on Windows 10
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1', # Chrome on Iphone
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0', # Firefox on Windows
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15', # Safari on macOS
    'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.99 Mobile Safari/537.36', # Chrome on Android
    'Mozilla/5.0 (X11; Linux i686; rv:124.0) Gecko/20100101 Firefox/124.0' # Firefox on Linux
]

public_hosts = {
    "http://1.0.0.1/": 0, # Cloudflare
    "http://1.1.1.1/": 0, # Cloudflare
    "http://208.67.220.220/": 0, # OpenDNS
    "http://208.67.222.222/": 0 # OpenDNS
}

def count_public_hosts_requests():
    total = 0
    for h in public_hosts:
        total += public_hosts[h]
    return total

def check_connectivity():
    tries = 3
    while tries:
        tries -= 1

        host = min(public_hosts, key=public_hosts.get)

        try:
            r = requests.head( host, headers={
                'User-Agent': random.choice(user_agents)
            }, allow_redirects=False, timeout=timeout )
            public_hosts[ host ] += 1
            return True
        except Exception:
            pass

        if tries:
            print( yellow('[!] Warning: Unable to resolve the public hosts! Retrying after 5 seconds...') )
            time.sleep(5)
        else:
            print( red('[!] Error: Failed to resolve the public hosts! Check your connection.') )
            return False

def get_endpoint_ready( url ):
    endpoint = url
    if url.startswith('http://'):
        endpoint = url[7:]
    elif url.startswith('https://'):
        endpoint = url[8:]

    endpoint = '/'.join(endpoint.split('?')[0].split('/')[1:])

    if is_valid_endpoint(endpoint):
        return endpoint + ('' if endpoint.endswith('/') else '/')
    else:
        return ''

def colored_codes( status_code, endpoint='' ):
    c = str(status_code)
    if endpoint:
        c = endpoint + ' [' + c + ']'

    if status_code == 200:
        c = green(c)
    elif status_code in redirections_codes:
        c = cyan(c)
    elif status_code in [401, 403]:
        c = yellow(c)
    elif status_code == 500:
        c = red(c)

    return c

def get_pattern( item, pattern ):
    return item.replace('~', '\~').replace('-', '\-').replace('.', '\.').replace('*', pattern)

def endpoints_checker( url, check_connection, delay, first_req, force, validate, exclude, recursive, save, recursive_level=0 ):
    global ok_status, total_status
    print( cyan('[~] Fuzzing endpoints for target "' + url + '"...') )

    endpoint = get_endpoint_ready(url)
    if url.startswith('https://'):
        url = 'https://' + url[8:].split('/')[0] + '/'
    else:
        url = 'http://' + url[7:].split('/')[0] + '/'

    wordlist = [] if (validate and not force) else load_list('endpoints')
    wordlist = [ endpoint + _ for _ in wordlist ]

    if validate or save or (not force and not validate):
        host = get_target_host( url )
        port = str(get_target_port_or_none(url))
        database = load_database( host )

    if validate:
        if port in database['endpoints']:
            for k in database['endpoints'][port]:
                if k not in wordlist and ((k.startswith(endpoint) and k != endpoint) or not endpoint):
                    wordlist.append(k)

        if not wordlist:
            if force:
                print( red('[!] Error: No endpoints to scan/validate! Check your lists.') )
            else:
                print( red('[!] Error: No endpoints to validate! Check your lists.') )
            return

    if not wordlist:
        print( red('[!] Error: No endpoints to scan! Check your lists.') )
        return

    if not force and not validate:
        if port in database['endpoints']:
            for e in database['endpoints'][port]:
                wordlist = [ _ for _ in wordlist if _ != e ]

        if not wordlist:
            print( yellow('[!] Warning: Endpoints already scanned, Use -F/--force option to force scan.') )
            return

    if exclude:
        for item in exclude:
            exclude_pattern = '[A-Za-z0-9 /\~_\-\.\*]+'
            if re.compile(exclude_pattern).fullmatch(item):
                pattern = get_pattern(item, exclude_pattern)
                endpoint_pattern = get_pattern(endpoint, exclude_pattern) + pattern
                wordlist = [ _ for _ in wordlist if
                    not re.compile(pattern).fullmatch(_)
                    and not re.compile(endpoint_pattern).fullmatch(_) 
                ]

        if not wordlist:
            print( red('[!] Error: No endpoints left to scan! Try to remove -E/--exclude option.') )
            return

    for endpoint in wordlist:
        if first_req:
            first_req = False
        elif delay:
            time.sleep(delay)

        t = url + endpoint

        if check_connection and not check_connectivity():
            break

        try:
            r = requests.get( t, headers={
                'User-Agent': random.choice(user_agents)
            }, allow_redirects=False, timeout=timeout )
            total_status += 1

            # Mislead detection
            if r.status_code == 200 and 'window.__NUXT__' and '/_nuxt/' and 'id="nuxt-loading"' in r.text:
                print( yellow('[!] Warning: NUXT app detected, All endpoints may be treated as 200! Skipping...') )
                break
            elif r.status_code == 400 and 'The plain HTTP request was sent to HTTPS port' in r.text:
                print( red('[!] Error: The plain HTTP request was sent to HTTPS port.') )
                break
            elif r.status_code == 429:
                print( yellow('[!] Warning: The scan detected by the server, -D/--delay option with a high number could be useful.') )
                break

            if r.status_code == 200:
                ok_status += 1

            if r.status_code != 404:
                print( green('[+] ') + colored_codes(r.status_code) + ' => ' + t )

            if save:
                if int(port) not in database['ports']['found']:
                    print( cyan('[~] Adding port "' + port + '" to the ports list...') )
                    database['ports']['found'].append(int(port))

                while int(port) in database['ports']['not_found']:
                    database['ports']['not_found'].remove(int(port))

                if port not in database['endpoints']:
                    database['endpoints'][ port ] = {}
                database['endpoints'][ port ][ endpoint ] = r.status_code

                update_database( host, database )

            if r.status_code in redirections_codes and 'Location' in r.headers:
                print( '        ' + cyan(r.headers['Location']) )
            elif recursive and r.status_code in [200, 403] and t.endswith('/') and recursive_level < max_recursive:
                database = endpoints_checker( t, check_connection, delay, first_req, force, validate, exclude, recursive, save, recursive_level+1 )

        except requests.exceptions.SSLError:
            print( red('[!] Error: SSL Error! Try HTTP protocol.') )
            break
        except requests.exceptions.Timeout:
            print( red('[!] Error: Connection time out.') )
            break
        except requests.exceptions.ConnectionError:
            print( red('[!] Error: Connection error.') )
            break

    if save:
        return database

def endpoints_scanner( target, check_connection, delay, force, validate, exclude, recursive, save ):
    host = get_target_host( target )
    passed_port = get_target_port_or_none( target )

    ports = [passed_port] if passed_port else load_database(host)['ports']['found']
    ports = [ str(p) for p in ports ]
    if not ports:
        if target.startswith('https://'):
            ports = ['443']
        else:
            ports = ['80']

    if len(ports) > 1:
        protcol = 'HTTP'
        if target.startswith('https://'):
            protcol = 'HTTPS'
        elif not target.startswith('http://') and '443' in ports:
            protcol = 'HTTP/S'
        print( cyan('[~] Checking ' + protcol + ' protcol for ports [' + ', '.join(ports) + '].') )

    for port in ports:
        scheme = 'http://'
        if target.startswith('https://') or (port == '443' and not target.startswith('http://')):
            scheme = 'https://'
        url = scheme + host + ':' + port + '/' + get_endpoint_ready(target)

        first_req = True
        endpoints_checker( url, check_connection, delay, first_req, force, validate, exclude, recursive, save )

    if save:
        database = load_database(host)
        database['endpoints']['last_scan'] = time.strftime("%Y/%m/%d %I:%M:%S %p")
        update_database( host, database )

    scan_stats = '[~] Finished! [' + str(ok_status) + '/' + str(total_status) + '] 200 OK'
    if check_connection:
        scan_stats += ', Total public hosts requests "' + str(count_public_hosts_requests()) + '"'
    print( cyan( scan_stats + '.' ) )
