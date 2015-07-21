# etcd vulnerability scanner
# v1 (2015-Jul-20)
# by eric barch (ericbarch.com)
# REQUIREMENTS: netaddr


# imports
import sqlite3
from os.path import isfile
import httplib
import time
import json
import signal
import sys
from netaddr import IPNetwork


# check if the script is being invoked with the IP prefix or not
if len(sys.argv) != 2:
    print 'EXAMPLE USAGE: python scan.py 45.55.0.0/16'
    sys.exit(0)


# define our database to store scanned hosts
sqlite_file = 'db.sqlite'

# do we need to create the DB?
create_db = False
if not isfile(sqlite_file):
    create_db = True

# 'connect' to the sqlite database
db = sqlite3.connect(sqlite_file)
cursor = db.cursor()

# create the schema we'll use to insert records (if the DB doesn't exist yet)
if create_db:
    print 'db does not exist, creating...'
    cursor.execute('CREATE TABLE etcdscan(ip TEXT PRIMARY KEY, port INTEGER, version TEXT, etcd_found INTEGER, scan_date INTEGER)')

# catch sigint so we don't f*ck the db
def signal_handler(signal, frame):
    print 'saving db and exiting...'
    # commit db changes and close
    db.commit()
    db.close()
    sys.exit(1)

# register the sigint handler
signal.signal(signal.SIGINT, signal_handler)


# break down our IP prefix into individual IPs
ip_range = IPNetwork(sys.argv[1])
# holds our list of IPs (strings) to scan
ips = list(ip_range)


# etcd 0.4.8 has a different version string, we normalize here
def filter_for_etcd_048(resp):
    if 'releaseVersion' in resp:
        parsed_json = json.loads(resp)
        return 'etcd ' + parsed_json['releaseVersion']
    elif 'etcd' in resp:
        return resp
    else:
        return None


# scan an IP for an etcd instance
def request_etcd_version(ip):
    try:
        # try port 2379 first
        conn = httplib.HTTPConnection(ip, 2379, timeout=0.5)
        conn.request('GET', '/version')
        res = conn.getresponse()
        if res.status != 200:
            raise Exception('Not an etcd host')
        else:
            return (filter_for_etcd_048(res.read()), 2379)
    except:
        try:
            # well let's try 4001 then
            conn = httplib.HTTPConnection(ip, 4001, timeout=0.5)
            conn.request('GET', '/version')
            res = conn.getresponse()
            if res.status != 200:
                raise Exception('Not an etcd host')
            else:
                return (filter_for_etcd_048(res.read()), 4001)
        except:
            # couldn't connect
            return (None, None)


# scan ip range
for ip_addr in ips:
    # convert IPNetwork object into string representation
    ip = str(ip_addr)

    # check if we've scanned this IP before, skip if so
    cursor.execute('SELECT rowid FROM etcdscan WHERE ip = ?', (ip, ))
    data = cursor.fetchall()
    if len(data) == 0:
        print 'scanning ' + ip
        resp, port = request_etcd_version(ip)

        if not resp == None:
            print resp + ' found'
        else:
            print 'host did not respond'

        found_etcd = 0 if resp == None else 1
        now = int(time.time())

        # store the result in the DB
        cursor.execute('INSERT INTO etcdscan VALUES (?, ?, ?, ?, ?)', (ip, port, resp, found_etcd, now, ))
    else:
        print 'already scanned ' + ip


# commit db changes and close
db.commit()
db.close()