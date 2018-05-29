"""
Databases functions handling the interactions with the database file
"""

import sqlite3

NAME_DB = "database.db"

"""
Function 'setupDb' sets up the database, creates tables if needed and initialises user data
"""
def setupDb(userList):
	try:
		tableNotCreated = createDb()
		if (!tableNotCreated):
			print "DB has been setup"
			#Init user data
		else:
			print "DB has not been setup"
	except:
		pass

"""
Function 'createDb' creates the tables if they don't exist
"""
def createDb():
	conn = sqlite3.connect(NAME_DB)
	queryCurs = conn.cursor()
	try:
		queryCurs.execute('''CREATE TABLE IF NOT EXISTS Users()''')
		queryCurs.execute('''CREATE TABLE IF NOT EXISTS Profiles()''')
		queryCurs.execute('''CREATE TABLE IF NOT EXISTS Messages_Files()''')

	except:
		conn.close()
		return 1;
	conn.commit()
	conn.close()
	return 0

"""
Function 'initUserData' initialises user data if they don't exist
"""
def initUserData(userList):
	try:
		conn = sqlite3.connect(NAME_DB)
		queryCurs = conn.cursor()
		for username in userList:
			queryCurs.execute()
			data = queryCurs.fetchone()
			if data is None:
				queryCurs.execute('''INSERT INTO Users()''')
		conn.commit()
		conn.close()
	except:
		pass

