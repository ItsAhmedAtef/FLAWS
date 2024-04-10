#!/usr/bin/env python3
# -*- coding: utf-8 -*-

try:
    ###############
    __import__('sys').dont_write_bytecode = True
    import random
    import argparse

    from flaws_utils  import red, cyan, is_valid_target
    from flaws_ls     import list_target, list_targets
    from flaws_nmap   import ports_checker, subdomains_checker
    from flaws_fuzzer import endpoints_scanner
    ###############

    logo  = '  ______ _           _          _ _____ \n'
    logo += ' |  ____| |        /\ \        / / ____|\n'
    logo += '  | |__  | |       /  \ \  /\  / / (___ \n'
    logo += ' |  __| | |      / /\ \ \/  \/ / \___ \ \n'
    logo += '  | |    | |____ / ____ \  /\  /  ___) |\n'
    logo += ' |_|    |______/_/    \_\/  \/  |_____/ v1.0'
    description = [
        ' FIND LATEST AVAILABLE WEAKNESS SPOT ',
        ' FETCH  LOCAL  ASSETS  WITH  SECRETS ',
        '  F    0x4c    0x41    0x57    0x53  ',
        ' "There are always flaws."   - Eliot ',
        'https://github.com/ItsAhmedAtef/FLAWS'
    ]
    print( logo + '\n-- ' + cyan(random.choice(description)) + ' --\n' )

    parser = argparse.ArgumentParser()
    parser.add_argument( '-t', '--target', type=str, help='target to scan' )
    parser.add_argument( '-l', '--list', action='store_true', help='list target/targets and exit' )
    parser.add_argument( '-p', '--ports', action='store_true', help='check for open ports' )
    parser.add_argument( '-s', '--sub-domains', action='store_true', help='check for subdomains' )
    parser.add_argument( '-e', '--endpoints', action='store_true', help='scan target endpoints' )
    parser.add_argument( '-a', '--all', action='store_true', help='run all available scans' )
    parser.add_argument( '-C', '--check-connection', action='store_true', help='keep checking the internet connection' )
    parser.add_argument( '-D', '--delay', type=int, help='delay time between requests (in seconds)' )
    parser.add_argument( '-F', '--force', action='store_true', help='force scan' )
    parser.add_argument( '-V', '--validate', action='store_true', help='validating the scan results' )
    parser.add_argument( '-E', '--exclude', action='append', help='exclude items from the scan' )
    parser.add_argument( '-R', '--recursive', action='store_true', help='recursive scan' )
    parser.add_argument( '-S', '--save', action='store_true', help='save the results' )
    args = parser.parse_args()

    if args.target is not None:
        if is_valid_target( args.target ):
            if not args.list and not args.all and not args.ports and not args.sub_domains and not args.endpoints:
                exit( red('[!] Error: No action specified!') )

            if args.list:
                list_target( args.target )

            else:
                if args.all or args.ports:
                    ports_checker(
                        args.target,
                        args.check_connection,
                        args.delay,
                        args.force,
                        args.validate,
                        args.exclude,
                        args.recursive,
                        args.save
                    )
                if args.all or args.sub_domains:
                    subdomains_checker(
                        args.target,
                        args.check_connection,
                        args.delay,
                        args.force,
                        args.validate,
                        args.exclude,
                        args.recursive,
                        args.save
                    )
                if args.all or args.endpoints:
                    endpoints_scanner(
                        args.target,
                        args.check_connection,
                        args.delay,
                        args.force,
                        args.validate,
                        args.exclude,
                        args.recursive,
                        args.save
                    )
        else:
            exit( red('[!] Error: Target is not valid!') )

    elif args.list:
        list_targets()

    else:
        exit( red('[!] Error: No target selected!') )

except KeyboardInterrupt:
    exit('\nCtrl+C pressed, bye.')