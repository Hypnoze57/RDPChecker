#!/usr/bin/python3

import argparse
import subprocess
import logging
import sys
import datetime
from colorlog import ColoredFormatter
from random import randint


def init_parser():
    parser = argparse.ArgumentParser(description='RDP Checker')

    parser.add_argument('targets', action='store', help='File containing IPs/hostnames or direct IPs/Hostnames separated by comma')
    parser.add_argument('-d', '--domain', action='store', help='Active Directory Domain')
    parser.add_argument('-u', '--username', action='store', help='Active Directory Username')
    parser.add_argument('-p', '--password', action='store', help='Active Directory Password')
    parser.add_argument('-H', '--hash', action='store', help='NTHASH')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    return parser.parse_args()


def setup_logger(options):
    global logger
    logger = logging.getLogger("RDPChecker")

    if options.debug is True:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    log_colors = {
        'DEBUG': 'bold_red',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'blue',
    }
    formatter = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(formatter, datefmt='%d-%m-%Y %H:%M:%S', log_colors=log_colors)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    """
    # Create log-file handler
    log_filename = "rdpcheck." + datetime.datetime.now().strftime('%d-%m-%Y-%H-%M-%S-%f') + '.log'
    fh = logging.FileHandler(filename=log_filename, mode='a')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    """


def banner():
    banners = [
    """
  _____  _____  _____   _____ _               _
 |  __ \|  __ \|  __ \ / ____| |             | |
 | |__) | |  | | |__) | |    | |__   ___  ___| | _____ _ __
 |  _  /| |  | |  ___/| |    | '_ \ / _ \/ __| |/ / _ \ '__|
 | | \ \| |__| | |    | |____| | | |  __/ (__|   <  __/ |
 |_|  \_\_____/|_|     \_____|_| |_|\___|\___|_|\_\___|_|

    """,
    """
.------..------..------..------..------..------..------..------..------..------.
|R.--. ||D.--. ||P.--. ||C.--. ||H.--. ||E.--. ||C.--. ||K.--. ||E.--. ||R.--. |
| :(): || :/\: || :/\: || :/\: || :/\: || (\/) || :/\: || :/\: || (\/) || :(): |
| ()() || (__) || (__) || :\/: || (__) || :\/: || :\/: || :\/: || :\/: || ()() |
| '--'R|| '--'D|| '--'P|| '--'C|| '--'H|| '--'E|| '--'C|| '--'K|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'`------'`------'`------'`------'
    """,
    """
 (    (      (
 )\ ) )\ )   )\ )   (       )               )
(()/((()/(  (()/(   )\   ( /(    (       ( /(    (   (
 /(_))/(_))  /(_))(((_)  )\())  ))\  (   )\())  ))\  )(
(_)) (_))_  (_))  )\___ ((_)\  /((_) )\ ((_)\  /((_)(()\\
| _ \ |   \ | _ \((/ __|| |(_)(_))  ((_)| |(_)(_))   ((_)
|   / | |) ||  _/ | (__ | ' \ / -_)/ _| | / / / -_) | '_|
|_|_\ |___/ |_|    \___||_||_|\___|\__| |_\_\ \___| |_|

    """,
    """

 _____ ____  _____ _____ _           _
| __  |    \|  _  |     | |_ ___ ___| |_ ___ ___
|    -|  |  |   __|   --|   | -_|  _| '_| -_|  _|
|__|__|____/|__|  |_____|_|_|___|___|_,_|___|_|

    """,
    """

,------. ,------.  ,------.  ,-----.,--.                  ,--.
|  .--. '|  .-.  \ |  .--. ''  .--./|  ,---.  ,---.  ,---.|  |,-. ,---. ,--.--.
|  '--'.'|  |  \  :|  '--' ||  |    |  .-.  || .-. :| .--'|     /| .-. :|  .--'
|  |\  \ |  '--'  /|  | --' '  '--'\|  | |  |\   --.\ `--.|  \  \\   --.|  |
`--' '--'`-------' `--'      `-----'`--' `--' `----' `---'`--'`--'`----'`--'

    """,
    """
██████╗ ██████╗ ██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██████╔╝██║  ██║██████╔╝██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
██╔══██╗██║  ██║██╔═══╝ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║  ██║██████╔╝██║     ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═╝╚═════╝ ╚═╝      ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    """,
    ]

    print(banners[randint(0, len(banners)-1)])


def parse_targets(targets):
    try:
        f = open(targets)
        data = [s.strip() for s in f.readlines()]
        f.close()
        return data
    except:
        return targets.split(',')


def rdp_connection(target, domain, username, creds, pth=False):

    # https://github.com/xFreed0m/RDPassSpray
    success_login_yes_rdp = b"Authentication only, exit status 0"
    account_locked = b"ERRCONNECT_ACCOUNT_LOCKED_OUT"
    account_disabled = b"ERRCONNECT_ACCOUNT_DISABLED [0x00020012]"
    account_expired = b"ERRCONNECT_ACCOUNT_EXPIRED [0x00020019]"
    success_login_no_rdp = [b'[0x0002000D]', b'[0x00000009]', b'[0x00010009]'] # insufficient_privs added here #insufficient_privs = b"ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES [0x00010009]"
    #success_login_no_rdp = [b'0x0002000D', b'0x00000009']
    failed_to_conn_to_server = [b'0x0002000C', b'0x00020006']
    pass_expired = [b'0x0002000E', b'0x0002000F', b'0x00020013']
    failed_login = [b'0x00020009', b'0x00020014']

    if pth:
        cmd = "xfreerdp /v:'%s' +auth-only /d:%s /u:%s /p:'' '/pth:%s' /cert-ignore" % (target, domain, username, creds)
    else:
        cmd = "xfreerdp /v:'%s' +auth-only /d:%s /u:%s '/p:%s' /cert-ignore" % (target, domain, username, creds)

    co = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    co_stderr = co.stderr.read()
    co_stdout = co.stdout.read()

    logger.warning("Targeting %s with %s/%s:%s" % (target, domain, username, creds))
    logger.debug(cmd)

    """
    logger.debug(co_stdout.decode())
    logger.debug(co_stderr.decode())

    print("STATUS")
    print("======")
    print()
    print("STDOUT:")
    print(co_stdout.decode())
    print()
    print()
    print("STDERR:")
    print(co_stderr.decode())
    """


    if any(word in co_stderr for word in failed_to_conn_to_server):
        logger.error("[-] Failed to establish connection, check RDP availability.")
        return (False, 'No connection')
    elif any(word in co_stderr for word in failed_login):
        logger.error("[-] Authentication failed")
        return (False, 'Bad credentials')
    elif account_locked in co_stderr:
        logger.warning("[!] Account locked")
        return (False, 'Account locked')
    elif account_disabled in co_stderr:
        logger.warning("[*] Disabled account")
        return (True, 'Disabled account')
    elif any(word in co_stderr for word in pass_expired):
        logger.warning("[*] Password expired")
        return (True, 'Password expired')
    elif account_expired in co_stderr:
        logger.warning("[*] Account expired")
        return (True, 'Account expired')
    elif any(word in co_stderr for word in success_login_no_rdp):
        logger.warning("[+] Valid credentials but no RDP permissions")
        return (True, 'Valid, no RDP permissions')
    elif success_login_yes_rdp in co_stderr:
        logger.info("[+] Success ! %s" % (target))
        return (True, 'Success')
    else:
        logger.warning("[*] Unknown status")
        logger.debug(co_stdout.decode())
        logger.debug(co_stderr.decode())
        return (False, 'Unknown status')

if __name__ == '__main__':

    banner()
    options = init_parser()

    setup_logger(options)

    domain = options.domain
    username = options.username
    password = options.password

    if password == '' and username != '' and options.hash is None:
        from getpass import getpass
        password = getpass("Password:")

    targets = parse_targets(options.targets)

    logger.debug("Credentials: %s/%s:%s" % (domain, username, password))
    logger.debug("Targets: \n%s" % ("\n".join(targets)))

    for target in targets:
        if options.hash is not None:
            out = rdp_connection(target, domain, username, options.hash, pth=True)
        else:
            out = rdp_connection(target, domain, username, password, pth=False)
