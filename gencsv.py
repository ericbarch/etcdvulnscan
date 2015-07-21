# etcd vulnerability scanner CSV generator
# v1 (2015-Jul-20)
# by eric barch (ericbarch.com)


# imports
import csv
import sqlite3
import sys
from os.path import isfile


# define our database filename
sqlite_file = 'db.sqlite'

# does the db exist?
if not isfile(sqlite_file):
    print 'DB NOT FOUND'
    sys.exit(1)

# 'connect' to the sqlite database
db = sqlite3.connect(sqlite_file)
cursor = db.cursor()

# select all etcd hosts
cursor.execute('SELECT ip, port, version, scan_date from etcdscan WHERE etcd_found = 1')   

# open a file for writing the CSV to
file = open('etcd_hosts.csv', 'w')
csv_out = csv.writer(file, delimiter=',', quoting=csv.QUOTE_ALL)
# create the header
csv_out.writerow( ('IP', 'Port', 'Version', 'ScanTimestamp') )

# iterate over all the records
for record in cursor.fetchall():
    csv_out.writerow( record )

# close the file
file.close()