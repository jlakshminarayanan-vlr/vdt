#!/usr/bin/env python
"""
__author__ = "Keenan Matheny"
__credits__ = ["Keenan Matheny", "Christopher Morrow", "Fouad Sethna", "Kevin Hagopian"]
__license__ = "SPDX-License-Identifier: MIT"
__version__ = "1.0.0"
__status__ = "Beta"
__copyright__ = "Copyright (C) 2021 VMware, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in the 
Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
__title__ = "vCenter PostgresDB Check"
# TITLE = "vCenter PostgresDB Check"
REQUIRED_SERVICE = "vmware-vpostgres"

import os
import sys
sys.path.append(os.environ['VMWARE_PYTHON_PATH'])
parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
libdir = os.path.join(parentdir, 'lib')
sys.path.append(os.path.abspath(libdir))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pformatting import *
from utils import getSingleServiceStatus, getStartup, psqlQuery, Command, getDeployType
from vdt import setupLogging
import logging
logger = logging.getLogger(__name__)

def getPostgresSize():
	
	output_db, errors, timeout = Command(['du', '-sh', '/storage/db/vpostgres/']).run()
	output_pg = psqlQuery("select pg_size_pretty(pg_database_size('VCDB')) as vcdb_size;")
	output_pg = output_pg.replace('B','')
	output_pg = output_pg.replace(' ','')

	output_seat, errors, timeout = Command(['du', '-sh', '/storage/seat/vpostgres/']).run()
	print(color_wrap('Total Postgres Size:', 'subheading'))
	formResult("\t" + output_db.split()[0], color_wrap(output_db.split()[1], 'subheading'))
	formResult("\t" + output_seat.split()[0], color_wrap(output_seat.split()[1], 'subheading'))
	formResult("\t" + output_pg, color_wrap("Interpreted by vPostgres", 'subheading'))

def getLargestTables():
	print(color_wrap('Top 10 Largest Tables:\n', 'subheading'))

	query = """SELECT
  relname tablename,
  pg_size_pretty(table_size) AS size

FROM (
       SELECT
         pg_catalog.pg_namespace.nspname           AS schema_name,
         relname,
         pg_relation_size(pg_catalog.pg_class.oid) AS table_size

       FROM pg_catalog.pg_class
         JOIN pg_catalog.pg_namespace ON relnamespace = pg_catalog.pg_namespace.oid
     ) t
WHERE schema_name NOT LIKE 'pg_%'
ORDER BY table_size DESC LIMIT 10;"""

	output = psqlQuery(query, True)

	for line in output.splitlines():
		if "10 rows" not in line:
			print("  " + line)

def main_function():
	getLargestTables()
	getPostgresSize()

if __name__ == '__main__':
	if getDeployType() != 'infrastructure':
		setupLogging()
		# TITLE = color_wrap(TITLE,'title')
		# print(TITLE)
		req_service = REQUIRED_SERVICE
		service_status = getSingleServiceStatus(req_service)
		service_startup = getStartup(req_service)
		if service_status and service_startup == 'Automatic':
			main_function()
		elif service_status and service_startup != 'Automatic':
			print('Service: %s is disabled.' % req_service)		
		else:
			formResult(color_wrap("[FAIL]", 'fail'), "Service: %s is not started! It is required for this test to run." % req_service)
	else:
		print("Not applicable on this node.")