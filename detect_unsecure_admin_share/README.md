# detect_unsecure_admin_share.py
```
usage: detect_unsecure_admin_share.py [-h] (--ip IP | --file FILE | --net NET)
                                      [--timeout TIMEOUT] [--verbose]
                                      [--debug] [--threads THREADS]
                                      [--user USER] [--password PASSWORD]
                                      [--domain DOMAIN]

Checks if is possible to write to C$ via SMB with the provided credentials

optional arguments:
  -h, --help           show this help message and exit
  --ip IP              Single IP address to check
  --file FILE          File containing a list of IP addresses to check
  --net NET            Network CIDR to check (requires python netaddr library)
  --timeout TIMEOUT    Timeout on connection for socket in seconds
  --verbose            Verbose output for checking of commands
  --debug              Debug output for more verbosity
  --threads THREADS    Number of connection threads when checking file of IPs (default 10)
  --user USER          username and password are the user credentials required to authenticate the underlying SMB connection with the remote server.
  --password PASSWORD  username and password are the user credentials required to authenticate the underlying SMB connection with the remote server.
  --domain DOMAIN      The network domain. On windows, it is known as the workgroup. (optional)
```
