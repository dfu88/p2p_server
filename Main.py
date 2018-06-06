""" 
    Main.py

    COMPSYS302 - Software Design
    Author: Dylan Fu

    This program uses the CherryPy web server (from www.cherrypy.org).
"""

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10010

#Import built-in python libraries and frameworks
import base64
import binascii
import cherrypy
import codecs
import copy
import hashlib
import hmac, struct
import json
import mimetypes
import os, os.path
import pyotp
import sched, time
import socket
import sys, traceback
import string, random
import threading
import urllib2

#Import other python files
import Db
import Security
from Timer import Timer

class MainApp(object):

    #CherryPy Configuration
    # _cp_config = {'tools.encode.on': True, 
    #               'tools.encode.encoding': 'utf-8',
    #               'tools.sessions.on' : 'True',
    #              }                 

    """
    Function '__init__' initialises the database and user variables
    """
    def __init__(self):
        try:
            userList = self.userListServer()
            # print userList
            Db.createDb(userList)
            # print "init db"
        except:
            # print "did not init db"
            pass
        finally:
            self.loggedIn = False
            self.username = None
            self.hashPassword = None
            self.rsaKey = Security.generateRSAKey()
            self.pubkey = binascii.hexlify(self.rsaKey.publickey().exportKey("DER"))
            self.refreshMsg = False
            self.timer = Timer(60, self.reportServer)
            self.profileTimer = Timer(60, self.getAllOnlineProfiles)
            self.onlineList = self.getListServer()
            self.timer.start()
            self.profileTimer.start()
            self.timer.pause()
            cherrypy.engine.subscribe('stop', self.exitMainApp)
            # self.profileTimer.pause()

    # If they try somewhere we don't know, catch it here and send them to the right place.
    """The default page, given when we don't recognise where the request is for."""
    # Page = "I don't know where you're trying to go, so have a 404 Error.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        Page = file('default.html')
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self,username=None):
        if self.loggedIn:
            cherrypy.session['viewUserProfile'] = None
            cherrypy.session['viewUserMessage'] = None
            Page = file('index.html')
            return Page
        else:
            raise cherrypy.HTTPRedirect("/login")
        
    @cherrypy.expose
    def login(self):
        if self.loggedIn:
            raise cherrypy.HTTPRedirect('/')
        else:
            Page = file('login.html')
            return Page
        
    @cherrypy.expose
    def login2(self):
        if self.loggedIn:
            raise cherrypy.HTTPRedirect('/')
        else:
            if self.username is not None:
                secret = Db.getSecret(self.username)
                if secret is None or secret == '':
                    secret = self.generateSecret(self.username)
                    Db.saveSecret(self.username, secret)
                    Page = file('login2New.html')
                    return Page
                else:
                    Page = file('login2.html')
                    return Page
            else:
                raise cherrypy.HTTPRedirect("/login")

    @cherrypy.expose
    def authoriseTFA(self, code=None):
        if self.loggedIn:
            raise cherrypy.HTTPRedirect('/')
        elif code is not None:
            secret = Db.getSecret(self.username)
            totp = pyotp.TOTP(secret)
            print totp.now()
            try:
                int(code)
            except:
                raise cherrypy.HTTPRedirect("/login2")
            if int(totp.now()) == int(code):
                self.loggedIn = True
                self.timer.resume()
                raise cherrypy.HTTPRedirect('/')
            else:
                self.loggedIn = False
                raise cherrypy.HTTPRedirect("/login2")
        else:
            self.loggedIn = False
            self.username = None
            raise cherrypy.HTTPRedirect("/login")
      
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = self.authoriseUserLogin(username,password)
        if (error == 0):
            self.username = username;
            raise cherrypy.HTTPRedirect("/login2")
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        try:
            if self.loggedIn:
                response = self.logoffServer()
                if response == "0, Logged off successfully":
                    self.loggedIn = False
                    self.username = None
                    self.hashPassword = None
                    self.timer.pause()
                    self.profileTimer.pause()
        except:
            pass
        finally:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def message(self, username=None):
        if self.loggedIn:
            if username != None:
                cherrypy.session['viewUserMessage'] = username
            else:
                cherrypy.session['viewUserMessage'] = self.username
            Page = file('message.html')
            return Page
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def sendMessage(self, message=None, attachments=None):
        if self.loggedIn:
            sender = self.username
            destination = cherrypy.session['viewUserMessage']
            userData = Db.getUserDataAsList(destination)

            payload = {'sender': sender, 'destination': destination, 'message': '', 'stamp': str(round(float(time.time())))}

            if message is not u'':
                try:  
                    messagePayload = copy.deepcopy(payload)
                    messagePayload['message'] = message
                    
                    #Get highest encryption standard possible
                    enc = self.getHighestEncStandard(destination,4)
                    if enc == 3 and (len(messagePayload['message']) < 128):
                        enc = self.getHighestEncStandard(destination,2)

                    #Encrypt message payload in highest encryption standard possible
                    messagePayload = Security.encryptMessagesFiles(messagePayload, userData[0]['publicKey'], enc)
                    #Get response from destination node
                    if sender == destination:
                        request = urllib2.Request('http://0.0.0.0:' + str(listen_port) + '/receiveMessage' , self.encJSON(messagePayload), {'Content-Type': 'application/json'})
                    else:
                        request = urllib2.Request('http://' + userData[0]['ip'] +':' + userData[0]['port'] + '/receiveMessage' , self.encJSON(messagePayload), {'Content-Type': 'application/json'})
                    try:
                        response = urllib2.urlopen(request,timeout=5).read()
                    except:
                        response = "5: Timeout Error"

                    #Check if message received, then save message and message status
                    if destination != self.username and '0' in response:
                        messagePayload['messageStatus'] = "Message Received"
                        Db.saveMessage(messagePayload)
                    elif '0' not in response:
                        messagePayload['message'] = "FAILED: " + response
                        messagePayload['messageStatus'] = "Message Failed"
                        Db.saveMessage(messagePayload)
                except:
                    pass

            if attachments.file is not None:
                try:
                    path = "static/downloads/"
                    fileName = attachments.filename
                    content_type = mimetypes.guess_type(fileName)[0]
                    attachments = base64.b64encode(attachments.file.read())

                    if not os.path.exists(path):
                        os.makedirs(path)
                    file = open(path+fileName,"wb")
                    file.write(base64.b64decode(attachments))
                    file.close()


                    embeddedViewerHTML = '<a href="' + \
                        os.path.join("/static/downloads/", fileName) + '\" download>' + fileName + '</a>'
                    if 'audio/' in content_type:
                        embeddedViewerHTML = '<audio controls><source src="' + \
                            os.path.join("/static/downloads/", fileName) + '\" type=\"' + content_type + '\"></audio>'
                    if 'image/' in content_type:
                        embeddedViewerHTML = '<img src="' + \
                            os.path.join("/static/downloads/", fileName) + '\" alt=\"' + fileName + '\" width="320">'
                    if 'video/' in content_type:
                        embeddedViewerHTML = '<video width="320" height="240" controls><source src="' + \
                            os.path.join("/static/downloads/", fileName) + '\" type=\"' + content_type + '\"></video>'
                    
                    #Need to handle hashing and encryption later
                    filePayload = {'sender': self.username, 'destination': destination, 'file': attachments, 'content_type': content_type, 'filename': fileName, 'stamp': unicode(int(time.time()))}

                    enc = self.getHighestEncStandard(destination,4)
                    if enc == 3 and (len(filePayload['message']) < 128):
                        enc = self.getHighestEncStandard(destination,2)

                    filePayload = Security.encryptMessagesFiles(filePayload, userData[0]['publicKey'], enc)
                    if sender == destination:
                        request = urllib2.Request('http://0.0.0.0:' + str(listen_port) + '/receiveFile' , self.encJSON(filePayload), {'Content-Type': 'application/json'})
                    else:
                        request = urllib2.Request('http://' + userData[0]['ip'] +':' + userData[0]['port'] + '/receiveFile' , self.encJSON(filePayload), {'Content-Type': 'application/json'})
                    try:
                        response = urllib2.urlopen(request,timeout=5).read()
                    except:
                        response = "5: Timeout Error"

                    #Check if message received
                    if destination != self.username and '0' in response:
                        payload['message'] = embeddedViewerHTML
                        payload['messageStatus'] = "File Received"
                        Db.saveMessage(payload)
                    elif '0' not in response:
                        payload['message'] = embeddedViewerHTML
                        payload['messageStatus'] = "File Failed"
                        Db.saveMessage(payload)
                except:
                    pass

            raise cherrypy.HTTPRedirect("message/?username="+cherrypy.session['viewUserMessage'])
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self):
        if self.loggedIn:
            try:
                dictionary = cherrypy.request.json
                if ('sender' not in dictionary or 'destination' not in dictionary or 'message' not in dictionary or 'stamp' not in dictionary):
                    return '1: Missing Compulsory Field'
                dictionary = Security.decryptMessagesFiles(dictionary, self.rsaKey)
                if 'encryption' in dictionary and dictionary['encryption'] == '5':
                    return "9: Encryption Standard Not Supported"
                dictionary['messageStatus'] = "Message Received"
                Db.saveMessage(dictionary)
                self.refreshMsg = True
                return '0: Message Received'
            except:
                return '-1: Internal Error'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self):
        try:
            dictionary = cherrypy.request.json

            if ('sender' not in dictionary or 'destination' not in dictionary or 'file' not in dictionary or 'filename' not in dictionary or 'content_type' not in dictionary or 'stamp' not in dictionary):
                return ('1: Missing compulsory Field')
            
            dictionary = Security.decryptMessagesFiles(dictionary, self.rsaKey)

            if len(dictionary['file']) * 3 / 1024 > 5120 * 4:
                return ('1: File size exceeded 5 MB')
            
            path = "static/downloads/"
            if not os.path.exists(path):
                os.makedirs(path)
            file = open(path+dictionary['filename'],"wb")
            file.write(base64.b64decode(dictionary['file']))
            file.close()

            content_type = mimetypes.guess_type(dictionary['filename'])[0]
            embeddedViewerHTML = '<a href="' + \
                os.path.join("/static/downloads/", dictionary['filename']) + '\" download>' + dictionary['filename'] + '</a>'
            if 'audio/' in content_type:
                embeddedViewerHTML = '<audio controls><source src="' + \
                    os.path.join("/static/downloads/", dictionary['filename']) + '\" type=\"' + dictionary['content_type'] + '\"></audio>'
            if 'image/' in content_type:
                embeddedViewerHTML = '<img src="' + \
                    os.path.join("/static/downloads/", dictionary['filename']) + '\" alt=\"' + dictionary['filename'] + '\" width="320">'
            if 'video/' in content_type:
                embeddedViewerHTML = '<video width="320" height="240" controls><source src="' + \
                    os.path.join("/static/downloads/", dictionary['filename']) + '\" type=\"' + dictionary['content_type'] + '\"></video>'
            payload = {'sender': dictionary['sender'], 'destination': dictionary['destination'], 'message': embeddedViewerHTML, 'stamp': dictionary['stamp'], 'messageStatus': "File Received"}

            Db.saveMessage(payload)
            
            self.refreshMsg = True

            return '0: File Received'
        except:
            return '-1: Internal Error'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def handshake(self):
        try:
            data = cherrypy.request.json
            if int(data['encryption']) == 1:
                data['message'] = Security.XORDecrypt(data['message'])
            if int(data['encryption']) == 2:
                data['message'] = Security.AESDecrypt(data['message'], '41fb5b5ae4d57c5ee528adb078ac3b2e')
            if int(data['encryption']) == 3:
                data['message'] = Security.RSADecryptKey(data['message'], self.rsaKey)
            if int(data['encryption']) == 4:
                data['decryptionKey'] = Security.RSADecryptKey(data['decryptionKey'], self.rsaKey)
                data['message'] = Security.AESDecrypt(data['message'], data['decryptionKey'])
            return {'error': u'0: Message Decrypted', 'message': data['message']}
        except:
            return {'error': u'-1: Internal Error', 'message': data['message']}


    def getHighestEncStandard(self, destination, index):
        userData = Db.getUserDataAsList(destination)
        alphabet = string.letters
        randomString = ''
        for i in range(16):
            randomString += random.choice(alphabet)
        
        while index > 0:
            try:
                data = {'sender': self.username, 'destination': destination, 'message': randomString}
                data['encryption'] = str(index)
                data = Security.encryptMessagesFiles(data, self.pubkey, index)
                request = urllib2.Request('http://' + userData[0]['ip'] +':' + userData[0]['port'] + '/handshake' , self.encJSON(data), {'Content-Type': 'application/json'})
                response = urllib2.urlopen(request).read()
                response = self.decJSON(response)
                print response
                print response['message']
                print randomString
                if response['message'] == randomString:
                    return index
            except:
                pass
            index = index - 1
        return 0

    @cherrypy.expose
    def viewProfile(self, username=None):
        if username != None:
            cherrypy.session['viewUserProfile'] = username
        else:
            cherrypy.session['viewUserProfile'] = self.username
        Page = file('viewProfile.html')
        return Page

    @cherrypy.expose
    def editProfile(self,fullname=None,position=None,description=None,location=None,imgURL=None):
        if self.loggedIn:
            if fullname != None or position != None or description != None or location != None or imgURL != None:
                raise cherrypy.HTTPRedirect("/")    
            else:
                cherrypy.session['viewUserProfile'] = self.username
                return file('editProfile.html')
        else:
            raise cherrypy.HTTPRedirect("/")

    @cherrypy.expose
    def updateProfile(self,fullname=None,position=None,description=None,location=None,imgURL=None):
        if fullname == None:
            fullname = "N/A"
        if position == None:
            position = "N/A"
        if description == None:
            description = "N/A"
        if location == None:
            location = "N/A"
        if imgURL == None or ('http://' not in imgURL and 'https://' not in imgURL):
            imgURL = "/static/placeholder.png"
        data = {'fullname': fullname, 'position': position, 'description': description, 'location': location, 'picture': imgURL, 'lastUpdated': round(float(time.time()))}
        Db.saveProfile(data, self.username)
        raise cherrypy.HTTPRedirect("/viewProfile/?username="+cherrypy.session['viewUserProfile'])

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def getProfile(self):
        dictionary = cherrypy.request.json
        if 'profile_username' not in dictionary or 'sender' not in dictionary:
                return ('1: Missing compulsory Field')
        data = Db.getProfile(dictionary['profile_username'])
        if data == None:
            return ('4: Profile Not Found')
        else:
            outputData = {}
            outputData['fullname'] = data[2]
            outputData['position'] = data[3]
            outputData['description'] = data[4]
            outputData['location'] = data[5]
            outputData['picture'] = data[6]
            outputData['encoding'] = data[7]
            outputData['encryption'] = data[8]
            outputData['decryptionKey'] = data[9]
            outputData['lastUpdated'] = data[11]
            finalData = self.encJSON(outputData)
            return finalData

    @cherrypy.expose
    def ping(self, sender=None):
        if sender != None:
            return ('0')
        else:
            return('1: Missing required field')
        
    """
    Function 'authoriseUserLogin' reports to the server for the first time
    """    
    def authoriseUserLogin(self, username, password):
        hashPassword = hashlib.sha256(password+username).hexdigest()
        # print username
        # print password
        # print hashPassword
        
        response = self.reportServer(username,password)
        if response == "0, User and IP logged":
            self.username = username
            self.hashPassword = hashlib.sha256((password+username)).hexdigest()
            # print "sadajhsd"
            return 0
        else:
            # print "sadajhsd12133"
            # print response
            return 1

    def generateSecret(self, username):
        alphabet = string.letters
        randomString = ""
        for i in range(9):
            randomString += random.choice(alphabet)
        return base64.b32encode(username[:4] + randomString)[:16]

    def retrieveQRCode(self,username,secret):
        return "https://chart.googleapis.com/chart?chs=175x175&chld=M%7C0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2F" + username + "%3Fsecret%3D" + secret + "%26issuer%3DP2P"

    """
    Function encJSON encodes data in a dictionary into JSON data
    """
    def encJSON(self,dictionary):
        return json.dumps(dictionary)

    """
    Function decJSON decodes JSON data into a dictionary
    """    
    def decJSON(self,data):
        return json.loads(data)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getUserListJSON(self):
        data = Db.getAllUserDataAsList()
        onlineList = self.encJSON(self.onlineList)

        for user in data:
            lastLogin = time.strftime(
                "%H:%M:%S, %d/%m/%Y", time.localtime(float(user['lastLogin'] or 0)))
            if int(user['lastLogin'] or 0) + 86400 > int(time.time()):
                user['lastLogin'] = time.strftime("%H:%M:%S", time.localtime(float(user['lastLogin'] or 0)))
            elif user['lastLogin'] == None:
                user['lastLogin'] = 'NEVER'
            elif int(user['lastLogin'] or 0) == 0:
                user['lastLogin'] = 'NEVER'
            else:
                user['lastLogin'] = time.strftime("%a, %d %b %Y", time.localtime(float(user['lastLogin'] or 0)))

            if user['username'] in onlineList:
                user['onlineStatus'] = True
                user['lastLogin'] = 'ONLINE'
            else:
                user['onlineStatus'] = False

        finalData = {str(k): v for k, v in enumerate(data)}
        return finalData

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getMessageListJSON(self):
        data = Db.getMessages(cherrypy.session['viewUserMessage'], self.username)
        for row in data:
            row['stamp'] = time.strftime("%H:%M:%S, %d/%m/%Y", time.localtime(float(row['stamp'] or 0)))
            # row['message'] = string.replace(row['message'], "''", "'")
            row['username'] = row['sender']

        finalData = {str(k): v for k, v in enumerate(data)}
        return finalData

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getUserProfileJSON(self):
        data = Db.getProfileAsList(cherrypy.session['viewUserProfile'])
        if data == None:
            return ('4: Profile Not Found')
        else:
            finalData = {str(k): v for k, v in enumerate(data)}
            return finalData

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getSelfUsername(self):
        if self.loggedIn:
            username = str(self.username)
            return {'username': username}
        else:
            return {}


    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getTFAData(self):
        # if self.loggedIn:
        username = str(self.username)
        secret = Db.getSecret(username)
        return {'username': username, 'secret': secret}


    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getRefreshBoolean(self):
        if self.loggedIn:
            refreshMsg = self.refreshMsg
            if refreshMsg == True:
                self.refreshMsg = False
                return {'refreshMsg': True}
            return {'refreshMsg': False}

    ####### LOGIN SERVER AND PERIODICALLY CALLED FUNCTIONS########
    def reportServer(self,username=None,password=None):
        if username is None:
            username = self.username
        if password is None:
            password = self.hashPassword

        try:
            if self.hashPassword != password:
                hashPassword = hashlib.sha256(password+username).hexdigest()
            else:
                hashPassword = password

            data = self.decJSON(urllib2.urlopen("https://api.ipify.org/?format=json").read())
            ip = data['ip']
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ipLocal = s.getsockname()[0]
            s.close()

            if '10.10' in ipLocal:
                location = '0'
                ipFinal = ipLocal
            elif '172.2' in ipLocal:
                location = '1'
                ipFinal = ipLocal
            else:
                location = '2'
                ipFinal = ip

            url = "http://cs302.pythonanywhere.com/report/?username="+username.lower()+"&password="+hashPassword+"&location="+location+"&ip="+ipFinal+"&port="+str(listen_port)+"&enc=0&pubkey="+self.pubkey
            response = urllib2.urlopen(url, timeout=5).read()

            if '0' in response:
                if self.loggedIn == False:
                    self.username = username.lower()
                    self.hashPassword = hashPassword
                self.onlineList = self.getListServer()
                Db.updateUserData(self.onlineList)
                self.timer.resume()
            return response
        except:
            return "Internal error calling report API"

    def logoffServer(self):
        self.timer.pause()
        self.profileTimer.pause()
        url = "https://cs302.pythonanywhere.com/logoff?username=" + self.username + "&password=" + self.hashPassword + "&enc=0"
        response = urllib2.urlopen(url, timeout=5).read()
        return response

    def userListServer(self):
        try:
            url = "https://cs302.pythonanywhere.com/listUsers"
            response = urllib2.urlopen(url).read()
            return response.split(",")
        except:
            return []

    def getListServer(self):
        try:
            url = "https://cs302.pythonanywhere.com/getList?username=" + self.username + "&password=" + self.hashPassword + "&enc=0" + "&json=1"
            response = urllib2.urlopen(url).read()
            dictionary = self.decJSON(response)
            return dictionary
        except:
            return "Internal error calling getList API"

    def getAllOnlineProfiles(self):
        if self.loggedIn:
            data = Db.getAllUserDataAsList()
            onlineList = self.encJSON(self.onlineList)
            payload = {'sender': self.username}

            for user in data:
                try:
                    if user['username'] in onlineList:
                        payload['profile_username'] = user['username']
                        userData = Db.getUserDataAsList(user['username'])
                        request = urllib2.Request('http://'+ userData[0]['ip'] + ':' + userData[0]['port'] + '/getProfile', self.encJSON(payload), {'Content-Type': 'application/json'})
                        response = urllib2.urlopen(request, timeout=5).read()
                        if len(response) != 0 and response != None and 'lastUpdated' in response:
                            dictionary = self.decJSON(response)
                            Db.saveProfile(dictionary, user['username'])
                except:
                    pass
            self.profileTimer.resume()
    
    def exitMainApp(self):
        self.timer.pause()
        self.profileTimer.pause()
        if self.loggedIn:
            response = self.logoffServer()
            print response

def runMainApp():
    # HTML Secure Headers to help prevent html injection and cross site scripting attacks
    _csp_sources = ['default', 'script', 'style', 'img', 'connect', 'font', 'object', 'media', 'frame']
    _csp_default_source = "'self'"
    _csp_rules = list()
    for c in _csp_sources:
        _csp_rules.append('{:s}-src {:s}'.format(c, _csp_default_source))
    _csp = '; '.join(_csp_rules)

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/", {
        '/': {
            # 'tools.secureheaders.on': True,
            'tools.encode.on': True, 
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on' : 'True',
            'tools.response_headers.on': True,
            'tools.response_headers.headers': [
                ('X-Frame-Options', 'DENY'),  # [XFO]
                ('X-XSS-Protection', '1; mode=block'),  # [LUH]
                # ('Content-Security-Policy', _csp),  # [CSP]
                # ('X-Content-Security-Policy', _csp),  # [CSP]
                # ('X-Webkit-CSP', _csp),  # [CSP]
                ('X-Content-Type-Options', 'nosniff')  # [LUH]
            ],
            'tools.staticdir.root': os.path.abspath(os.getcwd()),
            
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        }
    })

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True,
                           })

    print "=============================="
    print "        Social Network        "
    print "          P2P Server          "
    print "=============================="                       

    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()
