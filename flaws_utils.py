# FLAWS Utilities

############################
if __name__ != 'flaws_utils':
    exit('[!] Error: Missing FLAWS context! Please do not call this file directly.')
############################

#########
import os
import random
import json
#########

working_dir = os.path.dirname(os.path.abspath( __file__ ))

capital_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
lower_chars   = 'abcdefghijklmnopqrstuvwxyz'
numbers       = '0123456789'

# Colors
def red(text):
    return '\x1b[31m' + str(text) + '\x1b[0m'
def green(text):
    return '\x1b[32m' + str(text) + '\x1b[0m'
def yellow(text):
    return '\x1b[33m' + str(text) + '\x1b[0m'
def cyan(text):
    return '\x1b[36m' + str(text) + '\x1b[0m'

def random_value(length):
    return ''.join( random.choice(lower_chars) for _ in range(length) )

def strip_target_scheme( target ):
    if target.startswith('http://'):
        target = target[7:]
    elif target.startswith('https://'):
        target = target[8:]

    return target

def get_target_host( target ):
    target = strip_target_scheme( target )
    target = target.split('/')[0]
    target = target.split(':')[0]

    return target

def is_valid_ip( host ):
    ip_parts = host.split('.')
    if len(ip_parts) != 4:
        return False

    for part in ip_parts:
        if not part or ( part.startswith('0') and part != '0' ):
            return False

        for i in part:
            if i not in numbers:
                return False

        if int(part) > 254:
            return False

    return True

def is_valid_host( host ):
    if host in ['localhost', '*.localhost']:
        return True

    if host.startswith('*.'):
        host = host[2:]

    reversed_parts = host.split('.')[::-1]
    if len(reversed_parts) < 2:
        return False

    TLD = True
    for part in reversed_parts:
        if not part or part.startswith('-') or part.endswith('-'):
            return False

        for char in part:
            if char not in lower_chars and (char not in numbers + '-' or TLD):
                return False
        TLD = False

    return True

def is_valid_target( target ):
    host = get_target_host( target )
    if is_valid_host( host ) or is_valid_ip( host ):
        return True

    return False

def is_valid_port( port ):
    port = str(port)
    if port and not port.startswith('0'):
        for i in port:
            if i not in numbers:
                return False
        port = int(port)
        if port > 0 and port < 65536:
            # 1 - 65535
            return True
    return False

def get_target_port_or_none( target ):
    target = strip_target_scheme( target )
    target = target.split('/')[0]

    if ':' in target:
        port = target.split(':')[1]
        if is_valid_port( port ):
            return int(port)

    return None

def get_targets():
    targets = []
    try:
        targets = os.listdir( os.path.join(working_dir, 'targets') )
    except Exception:
        exit( red('[!] Error: Failed to list the targets folder!') )

    targets = list(map(
        lambda t: (t[:-5] if t.endswith('.json') else t).replace('WILDCARD', '*'),
        targets
    ))
    targets.sort( key=lambda t: '.'.join(t.split('.')[::-1]) )

    return targets

def is_valid_endpoint( endpoint ):
    if not endpoint or endpoint.startswith('/') or '//' in endpoint:
        return False

    for c in endpoint:
        if c not in capital_chars + lower_chars + numbers + ' /~_-.':
            return False
    return True

def is_valid_subdomain_name_or_chain( name_or_chain ):
    for part in name_or_chain.split('.'):
        if not part or part.startswith('-') or part.endswith('-'):
            return False

        for char in part:
            if char not in lower_chars + numbers + '-':
                return False
    return True

def get_parent_domain( host, targets ):
    while host:
        host = '.'.join( host.split('.')[1:] )
        if host in targets:
            return host
    return None

def get_sub_domains( host , targets=None ):
    if targets is None:
        targets = get_targets()

    subdomains = []
    for t in targets:
        if t.endswith( '.' + host ) and is_valid_host( t ):
            subdomains.append(t)
    return subdomains

def delete_empty_target( host ):
    safe_delete = True

    target_path = os.path.join( working_dir, 'targets', host.replace('*', 'WILDCARD') + '.json' )
    if os.path.isfile( target_path ):
        try:
            f = open( target_path, 'r' )
            database = json.load(f)
            f.close()

            for i in database:
                for ii in database[i]:
                    if database[i][ii]:
                        safe_delete = False
                        break

            if safe_delete:
                os.remove(target_path)
            else:
                print( yellow('[!] Warning: Database for "' + host + '" is not empty! Delete skipped.') )
        except Exception:
            exit( red('[!] Error: Failed to check/delete the database for "' + host + '"!') )

def load_database( host ):

    database = {
        "ports": {
            "found": [],
            "not_found": [],
            "last_scan": ""
        },
        "subdomains": {
            "not_found": [],
            "last_scan": ""
        },
        "endpoints": {
            "last_scan": ""
        }
    }

    target_path = os.path.join( working_dir, 'targets', host.replace('*', 'WILDCARD') + '.json' )
    if os.path.isfile( target_path ):
        try:
            f = open( target_path, 'r' )
            database = json.load(f)
            f.close()
        except Exception:
            exit( red('[!] Error: Failed to load the database for "' + host + '"!') )

    return database

def update_database( host, database ):
    target_path = os.path.join( working_dir, 'targets', host.replace('*', 'WILDCARD') + '.json' )
    try:
        f = open( target_path, 'w' )
        json.dump( database, f )
        f.close()
    except Exception:
        exit( red('[!] Error: Failed to update the database for "' + host + '"!') )

def load_list( lists_name ):
    items = []

    try:
        lists_path = os.path.join( working_dir, 'lists', lists_name )
        for list_file in os.listdir( lists_path ):
            list_file_path = os.path.join( lists_path, list_file )
            if os.path.isfile( list_file_path ) and os.access(list_file_path, os.R_OK):
                f = open( list_file_path, 'r' )
                for line in f.read().splitlines():

                    before_hashtag = line.split('#')[0]
                    if lists_name == 'ports' and is_valid_port( before_hashtag ):
                        # Hashtag for comments
                        line = int( before_hashtag )

                    elif lists_name == 'subdomains' and is_valid_subdomain_name_or_chain( line ):
                        pass

                    elif lists_name == 'endpoints' and is_valid_endpoint( line ):
                        pass
                    else:
                        continue

                    if line not in items:
                        items.append( line )
                f.close()
    except Exception:
        pass

    return items
