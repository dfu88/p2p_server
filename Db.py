""" 
	Db.py

    COMPSYS302 - Software Design
    Author: Dylan Fu

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
		c.execute('''CREATE TABLE IF NOT EXISTS Users (id integer PRIMARY KEY, username text, ip text, location text, lastLogin text, port text, publicKey text, picture text)''')
		c.execute('''CREATE TABLE IF NOT EXISTS Profiles (id integer PRIMARY KEY, username text, fullname text, position text, description text, location text, picture text, encoding text, encryption text, decryptionKey text, secretKey text, lastUpdated text)''')
		c.execute('''CREATE TABLE IF NOT EXISTS Messages_Files(id integer PRIMARY KEY, sender text, destination text, message text, stamp text, encoding text, encryption text, hashing text, hash text, decryptionKey text, messageStatus text)''')
		initUserData(userList)
		initUserProfile(userList)
		c.close()
		conn.commit()
		conn.close()
		# print "createDb success"
		# return 1
	except:
		c.close()
		conn.close()
		# print "createDb falied"
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
				c.execute('''INSERT INTO Users(username, ip, location, lastLogin, port, publicKey, picture) VALUES (?,?,?,?,?,?,?)''',(username,"","","","","","/static/placeholder.png"))
		c.close()
		conn.commit()
		conn.close()
		# print "initUserData success"
	except:
		# print "initUserData failed"
		pass

def initUserProfile(userList):
	try:
		conn = sqlite3.connect(DB_NAME)
		c = conn.cursor()
		for username in userList:
			c.execute("SELECT rowid FROM Profiles WHERE username = ?",(username,))
			data = c.fetchone()
			if data is None:
				c.execute('''INSERT INTO Profiles(username, fullname, position, description, location, picture, encoding, encryption, decryptionKey, secretKey, lastUpdated) VALUES (?,?,?,?,?,?,?,?,?,?,?)''',(username,"N/A","N/A","N/A","N/A","/static/placeholder.png","","","","",""))
		c.close()
		conn.commit()
		conn.close()
		# print "initUserProfile success"
	except:
		# print "initUserProfile failed"
		pass

def updateUserData(data):
	# print "trying to update userdata"
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

def getAllUserDataAsList():
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute('SELECT * FROM Users')
	allUserData = [dict(zip(['rowid', 'username', 'ip', 'location', 'lastLogin', 'port', 'publicKey', 'picture'], row)) for row in c.fetchall()]
	conn.commit()
	conn.close()
	return allUserData

def getUserDataAsList(destination):
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("SELECT * FROM Users WHERE username=?", (destination,))
	userData = [dict(zip(['rowid', 'username', 'ip', 'location', 'lastLogin', 'port', 'publicKey', 'picture'], row)) for row in c.fetchall()]
	conn.commit()
	conn.close()
	return userData

def getPublicKey(destination):
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("SELECT publicKey FROM Users WHERE username=?",(destination,))
	data = c.fetchone()
	if data is None:
		return None
	return data[0]

def saveProfile(dictionary, username):
	"""
	Saves new data to a users profile.
	"""
	if dictionary.get('picture') is None or ('http://' not in dictionary.get('picture') and 'https://' not in dictionary.get('picture')):
		dictionary['picture'] = "/static/placeholder.png"
	if isinstance(dictionary, unicode):
		dictionary = ast.literal_eval(dictionary)
	conn = sqlite3.connect(DB_NAME)
	# Create a query cursor on the db connection
	c = conn.cursor()
	c.execute("SELECT rowid FROM Profiles WHERE username = ?", (username,))
	data = c.fetchone()
	if data == None:
	    c.execute('''INSERT INTO Profiles (username, fullname, position, description, location, picture, lastUpdated) VALUES (?,?,?,?,?,?,?)''', (username, dictionary.get('fullname'), dictionary.get('position'), dictionary.get('description'), dictionary.get('location'), dictionary.get('picture'), dictionary.get('lastUpdated')))
	else:
	    c.execute('''UPDATE Profiles SET username=?, fullname=?, position=?, description=?, location=?, picture=?, lastUpdated=? WHERE rowid=?''', [username, dictionary.get('fullname'), dictionary.get('position'), dictionary.get('description'), dictionary.get('location'), dictionary.get('picture'), dictionary.get('lastUpdated'), data[0]])
	c.close()
	conn.commit()
	conn.close()

	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("SELECT rowid FROM Users WHERE username = ?", (username,))
	data = c.fetchone()
	c.execute('''UPDATE Users SET username=?, picture=? WHERE rowid=?''', [username, dictionary.get('picture'), data[0]])
	c.close()
	conn.commit()
	conn.close()
	return True

def getProfile(username):
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("SELECT * FROM Profiles WHERE username=?", (username,))
	data = c.fetchone()
	c.close()
	conn.close()
	return data

def getProfileAsList(username):
    conn = sqlite3.connect(DB_NAME)
    # Create a query cursor on the db connection
    c = conn.cursor()
    c.execute("SELECT * FROM Profiles WHERE username = '{a}'".format(a=username))
    userProfileData = [dict(zip(['rowid', 'username', 'fullname', 'position', 'description', 'location', 'picture', 'encoding', 'encryption', 'decryptionKey', 'status', 'secretKey'], row)) for row in c.fetchall()]
    c.close()
    conn.commit()
    conn.close()
    return userProfileData

def saveMessage(dictionary):
	print " INSIDE DB"
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	print "ISIDE ISH"
	if dictionary.get('messageStatus') == None:
		dictionary['messageStatus'] = "Receive Unconfirmed"
	
	# c.execute('''INSERT INTO Messages_Files''')
	c.execute("SELECT rowid FROM Messages_Files WHERE sender=? and destination=? and stamp=? and hash=?", (dictionary.get('sender'), dictionary.get('destination'), dictionary.get('stamp'), dictionary.get('hash'),))
	data = c.fetchone()
	print "3193878749"
	if data == None:
		c.execute('''INSERT INTO Messages_Files(sender, destination, message, stamp, encoding, encryption, hashing, hash, decryptionKey, messageStatus) VALUES (?,?,?,?,?,?,?,?,?,?)''', (dictionary.get('sender'), dictionary.get('destination'), dictionary.get('message'), dictionary.get('stamp'), dictionary.get('encoding'), dictionary.get('encryption'), dictionary.get('hashing'), dictionary.get('hash'), dictionary.get('decryptionKey'), dictionary.get('messageStatus')))
		print "487989"
	print "YOOOOOOOOOO"
	c.close()
	conn.commit()
	conn.close()
	print "hkbhkbbk"
	return True

def getMessages(destination,sender):
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("SELECT * FROM Messages_Files WHERE sender='{a}' AND destination='{b}' OR sender='{b}' AND destination='{a}'".format(a=destination, b=sender))
	messageList = [dict(zip(['rowid', 'sender', 'destination', 'message', 'stamp', 'encoding', 'encryption','hashing', 'hash', 'decryptionKey','messageStatus'], row)) for row in c.fetchall()]
	c.close()
	conn.commit()
	conn.close()
	return messageList

def getSecret(username):
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("SELECT secretKey FROM Profiles WHERE username=?",(username,))
	data = c.fetchone()
	if data is None:
		return None
	return data[0]

def saveSecret(username, secret):
	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("SELECT rowid FROM Profiles WHERE username=?", (username,))
	data = c.fetchone()
	if data is None:
		c.execute('''INSERT INTO Profiles (username, secretKey) VALUES (?,?)''', (username, secret))
	else:
		c.execute('''UPDATE Profiles SET secretKey=? WHERE rowid=?''',[secret, data[0]])
	c.close()
	conn.commit()
	conn.close()
	return True