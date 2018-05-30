
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
import os, os.path
import sched, time
import socket
import sys, traceback
import string, random
import threading
import urllib2

#Import other python files
import Db
from Timer import Timer

class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }                 

    """
    Function '__init__' initialises the database and user variables
    """
    def __init__(self):
        try:
            userList = self.userListServer()
            print userList
            Db.createDb(userList)
            print "init db"
        except:
            print "did not init db"
            pass
        finally:
            self.loggedIn = False
            self.username = None
            self.hashPassword = None
            self.timer = Timer(60, self.reportServer)
            self.timer.start()
            self.timer.pause()
        pass

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
    def index(self):
        if self.loggedIn:
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
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        # username = cherrypy.session.get('username')
        # if (username == None):
        #     pass
        # else:
        #     cherrypy.lib.sessions.expire()
        # raise cherrypy.HTTPRedirect('/')
        try:
            if self.loggedIn:
                response = self.logoffServer()
                if response == "0, Logged off successfully":
                    self.loggedIn = False
                    self.timer.pause()
        except:
            pass
        finally:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def editProfile(self):
        if self.loggedIn:
            return file('editProfile.html')
        else:
            raise cherrypy.HTTPRedirect("/")


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
        print username
        print password
        print hashPassword
        
        response = self.reportServer(username,password)
        if response == "0, User and IP logged":
            self.username = username
            self.hashPassword = hashlib.sha256((password+username)).hexdigest()
            return 0
        else:
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
        print data
        for user in data:

            lastLogin = time.strftime(
                "%Y/%m/%d, %H:%M:%S", time.localtime(float(user['lastLogin'] or 0)))
            if int(user['lastLogin'] or 0) + 86400 > int(time.time()):
                user['lastLogin'] = time.strftime(
                    "%H:%M:%S", time.localtime(float(user['lastLogin'] or 0)))
            elif user['lastLogin'] == None:
                user['lastLogin'] = 'NEVER'
            elif int(user['lastLogin'] or 0) == 0:
                user['lastLogin'] = 'NEVER'
            else:
                user['lastLogin'] = time.strftime(
                    "%a, %d %b %Y", time.localtime(float(user['lastLogin'] or 0)))

        dataList = {str(k): v for k, v in enumerate(data)}
        return dataList

    ####### LOGIN SERVER ########
    def reportServer(self,username=None,password=None):
        # location = "2"
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
                ipFinal = localip
            elif '172.2' in ipLocal:
                location = '1'
                ipFinal = localip
            else:
                location = '2'
                ipFinal = ip

            url = "http://cs302.pythonanywhere.com/report/?username="+username.lower()+"&password="+hashPassword+"&location="+location+"&ip="+ipFinal+"&port="+str(listen_port)+"&enc=0"
            response = urllib2.urlopen(url).read()
            # Update User Data if already logged in
            #NOTE include self.loggedIn later
            if response == "0, User and IP logged":
                if self.loggedIn == False:
                    self.username = username.lower()
                    self.hashPassword = hashPassword
                data = self.getListServer()
                # print data
                Db.updateUserData(data)
                self.timer.resume()
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
          
def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/", {
        '/': {
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
    
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()