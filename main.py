
""" main.py

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


class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }                 

    # INITIALISE VARIABLES
    def  __init__(self):
        try:
            #Get userList
            #Initialise userList in DB
            pass
        except:
            pass
        finally:
            self.loggedIn = True
            self.username = None
            self.hashPassword = None
        pass

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        # Page = "I don't know where you're trying to go, so have a 404 Error."
        Page = file('default.html')
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        # Page = "Welcome! This is a test website for COMPSYS302!<br/>"
        
        # try:
        #     Page += "Hello " + cherrypy.session['username'] + "!<br/>"
        #     Page += "Here is some bonus text because you've logged in!"
        # except KeyError: #There is no username
            
        #     Page += "Click here to <a href='login'>login</a>."
        # return Page
        if self.loggedIn:
            Page = file('index.html')
            return Page
        else:
            raise cherrypy.HTTPRedirect("/login")
        
    @cherrypy.expose
    def login(self):
        # Page = '<form action="/signin" method="post" enctype="multipart/form-data">'
        # Page += 'Username: <input type="text" name="username"/><br/>'
        # Page += 'Password: <input type="text" name="password"/>'
        # Page += '<input type="submit" value="Login"/></form>'
        Page = file('login.html')
        return Page
    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = self.authoriseUserLogin(username,password)
        if (error == 0):
            self.username = username;
            self.loggedIn = True
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if (username == None):
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def ping(self, sender=None):
        if sender != None:
            return ('0')
        else:
            return('1: Missing required field')
        
    def authoriseUserLogin(self, username, password):
        hashPassword = hashlib.sha256(password+username).hexdigest()
        print username
        print password
        print hashPassword
        #NOTE IP and Location HARDCODED
        location = "2"
        url = "http://cs302.pythonanywhere.com/report/?username="+username.lower()+"&password="+hashPassword+"&location="+location+"&ip=127.0.0.1&port="+str(listen_port)+"&enc=0"
        response = urllib2.urlopen(url).read()
        if response == "0, User and IP logged":
            self.username = username
            self.hashPassword = hashPassword
            return 0
        else:
            return 1

    
          
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