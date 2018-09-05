#!/usr/bin/python

import binascii
import socket
import argparse
import struct
import threading
import time
import tempfile

from smb.SMBConnection import SMBConnection

# Arguments
parser = argparse.ArgumentParser(description="Checks if is possible to write to C$ via SMB with the provided credentials", formatter_class=argparse.RawTextHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--ip', help='Single IP address to check')
group.add_argument('--file', help='File containing a list of IP addresses to check')
group.add_argument('--net', help='Network CIDR to check (requires python netaddr library)')
parser.add_argument('--timeout', help="Timeout on connection for socket in seconds", default=None)
parser.add_argument('--verbose', help="Verbose output for checking of commands", action='store_true')
parser.add_argument('--debug', help="Debug output for more verbosity", action='store_true')
parser.add_argument('--threads', help="Number of connection threads when checking file of IPs (default 10)", default="10")
parser.add_argument('--user', help='username and password are the user credentials required to authenticate the underlying SMB connection with the remote server. ')
parser.add_argument('--password', help='username and password are the user credentials required to authenticate the underlying SMB connection with the remote server. ')
parser.add_argument('--domain', help='The network domain. On windows, it is known as the workgroup. (optional)', default="")

args = parser.parse_args()
ip = args.ip
user = args.user
password = args.password
domain = args.domain
filename = args.file
net = args.net
timeout = float(args.timeout)
verbose = args.verbose
debug = args.debug
num_threads = int(args.threads)
semaphore = threading.BoundedSemaphore(value=num_threads)
print_lock = threading.Lock()
target_counter_lock = threading.Lock()
target_counter = 0

def print_status(ip, message):
    global print_lock

    with print_lock:
        print "[*] [%s] %s" % (ip, message)


def check_ip(ip):
    global timeout, verbose, user, password, domain, print_lock, debug

    try:
        # Connect to socket
        conn = SMBConnection(user, password, "detect_unsecure_admin_share.py", ip, domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
        assert conn.connect(ip, 445, timeout=timeout)
        if debug:
            with print_lock:
                print("#DEBUG: Successfully connected to ip: {}".format(ip))
        
        f = tempfile.TemporaryFile()
        f.write("Hello World!\n")
        
        try:
            conn.storeFile("C$", "detect_unsecure_admin_share.tmp", f, timeout=timeout)
            with print_lock:
                print("#SUCCESS: Successfully stored test file on C$ admin share at ip: {}".format(ip))
        
            conn.deleteFiles("C$", "detect_unsecure_admin_share.tmp", timeout=timeout)
            if debug:
                with print_lock:
                    print("#DEBUG: Successfully deleted test file from C$ admin share at ip: {}".format(ip))
        except Exception as ex:
            if debug:
                with print_lock:
                    print("#ERROR: Could not store file on C$ admin share on ip: {}".format(ip))
        finally:
            conn.close()
            f.close()
    
    except socket.timeout:
        if debug:
            with print_lock:
                print("#DEBUG: Connection timed out for ip: {}".format(ip))
    except Exception as ex:
        if debug:
            with print_lock:
                print("#DEBUG: Connection failure for ip: {}".format(ip))

def threaded_check(ip_address):
    global semaphore, verbose, debug, target_counter_lock, target_counter

    try:
        check_ip(ip_address)
    finally:
        with target_counter_lock:
            target_counter += 1
        semaphore.release()

def counter_thread():
    global print_lock, target_counter_lock, host_count, target_counter, verbose, debug

    if verbose:
        percent_complete = 0.00
        while percent_complete < 100.00:
            percent_complete = (float(target_counter)/float(host_count))*100.00
            with target_counter_lock:
                with print_lock:
                    print("#INFO: Scan is {}% complete".format(percent_complete))
            if percent_complete == 100.00:
                break
            time.sleep(5)


if ip:
    check_ip(ip)

elif filename:
    with open(filename, "r") as fp:
        for line in fp:
            semaphore.acquire()
            ip_address = line.strip()
            t = threading.Thread(target=threaded_check, args=(ip_address,))
            t.start()
elif net:
    from netaddr import IPNetwork
    network = IPNetwork(net)
    host_count = 2**(32-network.prefixlen)-2
    if host_count < 1:
      host_count = 1
    print("#INFO: Script will scan {} hosts.".format(host_count))
    ct = threading.Thread(target=counter_thread)
    ct.start()
    for addr in network:
        # Skip the network and broadcast addresses
        if (network.size != 1) and ((addr == network.network) or (addr == network.broadcast)):
            continue
        semaphore.acquire()
        ip_address = str(addr)
        t = threading.Thread(target=threaded_check, args=(ip_address,))
        t.start()
