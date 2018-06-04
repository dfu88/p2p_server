
""" Main.py

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
            self.refreshMsg = False
            self.timer = Timer(60, self.reportServer)
            self.profileTimer = Timer(60, self.getAllOnlineProfiles)
            self.onlineList = self.getListServer()
            self.timer.start()
            self.profileTimer.start()
            self.timer.pause()
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
        Page = file('login.html')
        return Page
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = self.authoriseUserLogin(username,password)
        if (error == 0):
            self.username = username;
            self.loggedIn = True
            self.timer.resume()
            # print "sucessdjkafb"
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
            # print attachments
            # print attachments.file

            payload = {'sender': sender, 'destination': destination, 'message': '', 'stamp': str(round(float(time.time())))}
            if message is not u'':
                messagePayload = copy.deepcopy(payload)
                messagePayload['message'] = message
                #Need to handle hashing and encryption later
                request = None
                if sender == destination:
                    request = urllib2.Request('http://0.0.0.0:' + str(listen_port) + '/receiveMessage' , self.encJSON(messagePayload), {'Content-Type': 'application/json'})
                else:
                    request = urllib2.Request('http://' + userData[0]['ip'] +':' + userData[0]['port'] + '/receiveMessage' , self.encJSON(messagePayload), {'Content-Type': 'application/json'})
                try:
                    response = urllib2.urlopen(request,timeout=5).read()
                except:
                    response = "5: Timeout Error"

                #Check if message received
                if destination != self.username and '0' in response:
                    messagePayload['messageStatus'] = "Message Received"
                    Db.saveMessage(messagePayload)
                elif '0' not in response:
                    messagePayload['message'] = "FAILED: " + response
                    messagePayload['messageStatus'] = "Message Failed"
                    Db.saveMessage(messagePayload)

            if attachments.file is not None:
                path = "static/downloads/"
                fileName = attachments.filename
                # content_type = attachments.content_type.value
                content_type = mimetypes.guess_type(fileName)[0]
                # print content_type
                attachments = base64.b64encode(attachments.file.read())
                # print attachments
                if not os.path.exists(path):
                    os.makedirs(path)
                file = open(path+fileName,"wb")
                file.write(base64.b64decode(attachments))
                file.close()
                filePayload = {'sender': self.username, 'destination': destination, 'file': attachments, 'content_type': content_type, 'filename': fileName, 'stamp': unicode(int(time.time()))}
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
                request = None
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

            raise cherrypy.HTTPRedirect("message/?username="+cherrypy.session['viewUserMessage'])
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveMessage(self):
        # print "testing"
        try:
            dictionary = cherrypy.request.json
            print dictionary
            # for key in dictionary:
            #     dictionary[key] = unicode(dictionary[key])
            if ('sender' not in dictionary or 'destination' not in dictionary or 'message' not in dictionary or 'stamp' not in dictionary):
                return '1: Missing Compulsory Field'
            #Save message in database
            # if (unicode(dictionary['enc']) and 'encryption' in dictionary) != u'0':
            #     return "9: Encryption Standard Not Supported"
            dictionary['messageStatus'] = "Message Received"
            Db.saveMessage(dictionary)
            self.refreshMsg = True
            print self.refreshMsg
            # print "!!!!!!!!testing"
            return '0: Message Received'
        except Exception as e:
            return '-1: Internal Error'

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def receiveFile(self):
        try:
            dictionary = cherrypy.request.json
            if ('sender' not in dictionary or 'destination' not in dictionary or 'file' not in dictionary or 'filename' not in dictionary or 'content_type' not in dictionary or 'stamp' not in dictionary):
                return ('1: Missing compulsory Field')
            if len(dictionary['file']) * 3 / 1024 > 5120 * 4:
                return ('1: File size exceeded 5 MB')
            path = "static/downloads/"
            if not os.path.exists(path):
                os.makedirs(path)
            file = open(path+dictionary['filename'],"wb")
            file.write(base64.b64decode(dictionary['file']))
            file.close()
            # content_type = mimetypes.guess_type(dictionary['filename'])[0]
            embeddedViewerHTML = '<a href="' + \
                os.path.join("/static/downloads/", dictionary['filename']) + '\" download>' + dictionary['filename'] + '</a>'
            if 'audio/' in dictionary['content_type']:
                embeddedViewerHTML = '<audio controls><source src="' + \
                    os.path.join("/static/downloads/", dictionary['filename']) + '\" type=\"' + dictionary['content_type'] + '\"></audio>'
            if 'image/' in dictionary['content_type']:
                embeddedViewerHTML = '<img src="' + \
                    os.path.join("/static/downloads/", dictionary['filename']) + '\" alt=\"' + dictionary['filename'] + '\" width="320">'
            if 'video/' in dictionary['content_type']:
                embeddedViewerHTML = '<video width="320" height="240" controls><source src="' + \
                    os.path.join("/static/downloads/", dictionary['filename']) + '\" type=\"' + dictionary['content_type'] + '\"></video>'
            payload = {'sender': dictionary['sender'], 'destination': dictionary['destination'], 'message': embeddedViewerHTML, 'stamp': dictionary['stamp'], 'messageStatus': "File Received"}

            Db.saveMessage(payload)
            return '0: File Received'
        except:
            return '-1: Internal Error'

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
        if imgURL == None:
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
        # print data
        # onlineList = self.getListServer()
        onlineList = self.encJSON(self.onlineList)
        # print onlineList
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

        print "hjbhakakck"
        finalData = {str(k): v for k, v in enumerate(data)}
        return finalData

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getMessageListJSON(self):
        # username = cherrypy.serving.request.headers['Referer']
        # print username
        data = Db.getMessages(cherrypy.session['viewUserMessage'], self.username)
        for row in data:
            row['stamp'] = time.strftime("%H:%M:%S, %d/%m/%Y", time.localtime(float(row['stamp'] or 0)))
            # row['message'] = string.replace(row['message'], "''", "'")
            row['username'] = row['sender']

        finalData = {str(k): v for k, v in enumerate(data)}
        # print finalData
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
        # if self.loggedIn:
        username = str(self.username)
        return {'username': username}
        # else:
        #     cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def getRefreshBoolean(self):
        # if self.loggedIn:
        refreshMsg = self.refreshMsg
        if refreshMsg == True:
            # print "hdvsdvjsbvbkabhvbdkasbsjbjkdvb
            self.refreshMsg = False
            return {'refreshMsg': True}
            # self.refreshMsg = False
        return {'refreshMsg': False}

    ####### LOGIN SERVER AND PERIODICALLY CALLED FUNCTIONS########
    def reportServer(self,username=None,password=None):
        # location = "2"

        # print "388080491"
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
            # print "2313312214"
            # print ipLocal
            # print ip

            if '10.10' in ipLocal:
                location = '0'
                ipFinal = ipLocal
            elif '172.2' in ipLocal:
                location = '1'
                ipFinal = ipLocal
            else:
                location = '2'
                ipFinal = ip

            url = "http://cs302.pythonanywhere.com/report/?username="+username.lower()+"&password="+hashPassword+"&location="+location+"&ip="+ipFinal+"&port="+str(listen_port)+"&enc=0"
            # url = "http://cs302.pythonanywhere.com/report/?username=dfu987&password=74a852ce7fe588a5e8a0b18a7568ab37649f477393655d7a6fdc0f5f9af6bdcf&location=1&ip=172.23.45.207&port=10010&enc=0"
            response = urllib2.urlopen(url).read()
            # print "cancer"
            # print response
            # Update User Data if already logged in
            #NOTE include self.loggedIn later
            if '0' in response:
                if self.loggedIn == False:
                    self.username = username.lower()
                    self.hashPassword = hashPassword
                self.onlineList = self.getListServer()
                # print data
                Db.updateUserData(self.onlineList)
                self.timer.resume()
            # print "12313122141"
            return response
        except:
            return "Internal error calling report API"

    def logoffServer(self):
        url = "https://cs302.pythonanywhere.com/logoff?username=" + self.username + "&password=" + self.hashPassword + "&enc=0"
        response = urllib2.urlopen(url).read()
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
        # try:
        data = Db.getAllUserDataAsList()
        onlineList = self.encJSON(self.onlineList)
        payload = {'sender': self.username}
        # print onlineList
        for user in data:
            try:
                if user['username'] in onlineList:
                    # print user
                    # print user['username']
                    payload['profile_username'] = user['username']
                    userData = Db.getUserDataAsList(user['username'])
                    request = urllib2.Request('http://'+ userData[0]['ip'] + ':' + userData[0]['port'] + '/getProfile', self.encJSON(payload), {'Content-Type': 'application/json'})
                    response = urllib2.urlopen(request, timeout=3).read()
                    if len(response) != 0 and response != 0:
                        dictionary = self.decJSON(response)
                        Db.saveProfile(dictionary, user['username'])
            except:
                pass
        self.profileTimer.resume()


    # @cherrypy.tools.register('before_finalize', priority=60)
    # def secureheaders():
    #     headers = cherrypy.response.headers
    #     headers['X-Frame-Options'] = 'DENY'
    #     headers['X-XSS-Protection'] = '1: mode=block'
    #     headers['X-Content-Type-Options'] = 'nosniff'
    #     headers['Content-Security-Policy'] = "default-src='self'" #Potentially affects js
    
    def exitMainApp(self):
        self.timer.pause()
        self.profileTimer.pause()
        if self.loggedIn:
            response = self.logoffServer()
            print response

def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    _csp_sources = ['default', 'script', 'style', 'img', 'connect', 'font', 'object', 'media', 'frame']
    _csp_default_source = "'self'"
    _csp_rules = list()
    for c in _csp_sources:
        _csp_rules.append('{:s}-src {:s}'.format(c, _csp_default_source))
    _csp = '; '.join(_csp_rules)

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

            # we don't need to initialize the database for static files served by CherryPy
            # 'tools.db.on': False
        }
    })

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True,
                           })

    print "========================="
    print "University of Auckland"
    print "COMPSYS302 - Server"
    print "========================================"                       
    mainapp = MainApp()
    cherrypy.engine.subscribe('exit', MainApp().exitMainApp)

    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()
