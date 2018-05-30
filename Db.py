"""
Databases functions handling the interactions with the database file
"""

import sqlite3

DB_NAME = "serverDb.db"

"""
Function 'setupDb' sets up the database, creates tables if needed and initialises user data
"""
# def setupDb(userList):
# 	try:
# 		tableCreated = createDb()
# 		if (tableCreated == 0):
# 			print "DB has not been setup"
# 		else:
# 			print "DB has been setup"
# 			initUserData(userList)
# 	except:
# 		print "setupDb failed"
# 		pass

"""
Function 'createDb' creates the tables if they don't exist
"""
def createDb(userList):
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	try:
		c.execute('''CREATE TABLE IF NOT EXISTS Users (id integer PRIMARY KEY, username text, ip text, location text, lastLogin text, port text, publicKey text)''')
		c.execute('''CREATE TABLE IF NOT EXISTS Profiles (id integer PRIMARY KEY, username text, fullname text, position text, description text, location text, picture text, encoding text, encryption text, decryptionKey text, status text, secretKey text)''')
        # c.execute('''CREATE TABLE IF NOT EXISTS MessagesFiles (id integer PRIMARY KEY, sender text, destination text, message text, stamp text, encoding text, encryption text, hashing text, hash text, decryptionKey text, file text, filename text, content_type text, message_status text)''')
		initUserData(userList)
		c.close()
		conn.commit()
		conn.close()
		print "createDb success"
		# return 1
	except:
		c.close()
		conn.close()
		print "createDb falied"
		# return 0;
	

"""
Function 'initUserData' initialises user data if they don't exist
"""
def initUserData(userList):
	try:
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()
		for username in userList:
			c.execute("SELECT rowid FROM Users WHERE username = ?",(username,))
			data = c.fetchone()
			if data is None:
				c.execute('''INSERT INTO Users(username, ip, location, lastLogin, port, publicKey) VALUES (?,?,?,?,?,?)''',(username,"","","","",""))
		c.close()
		conn.commit()
		conn.close()
		print "initUserData success"
	except:
		print "initUserData failed"
		pass

def updateUserData(data):
	print "trying to update userdata"
	try:
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()
		index = 0
		while str(index) in data:
			user = data[str(index)]
			c.execute("SELECT rowid FROM Users WHERE username=?", (user['username'],))
			tableData = c.fetchone()
			if tableData == None:
				index += 1
				continue
			else:
				c.execute('''UPDATE Users SET username=?, ip=?, location=?, lastLogin=?, port=?, publicKey=? WHERE rowid=?''', [user['username'], user['ip'], user['location'], user['lastLogin'], user['port'], user.get('publicKey'), tableData[0]])
			index += 1
		c.close()
		conn.commit()
		conn.close()
		print "Updated user table successfully"
	except:
		print "Error updating user data table"

def getAllUserData():
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute('SELECT * FROM Users')
	allUserData = c.fetchall()
	conn.commit()
	conn.close()
	return allUserData