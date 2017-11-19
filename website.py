import os, os.path
import sqlite3

import cherrypy
import hashlib
import os
from Crypto.Cipher import AES
from Crypto import Random
import base64


DB_STRING = "messages.db"


class StringGenerator(object):
    @cherrypy.expose
    def index(self):
        return open('index.html')


@cherrypy.expose
class StringGeneratorWebService(object):

    def __init__(self): 
        self.bs = 32
        self.iv = Random.new().read(AES.block_size)

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    @cherrypy.tools.accept(media='text/plain')
    def GET(self, code):
        #Set up AES cipher
        key = hashlib.sha256(code.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, self.iv)
        #Encrypt code
        code = base64.b64encode(self.iv + cipher.encrypt(self._pad(code)))

        #Search for encrypted code in table
        with sqlite3.connect(DB_STRING) as c:
            message = c.execute("SELECT message FROM data WHERE code=?",
                          [code])
            c.execute("DELETE FROM data WHERE code=?", [code])
            enc = message.fetchone()

        #fix the data
        if enc is None:
            return "No data found."
        enc = enc[0]

        #decrypt the message
        enc = base64.b64decode(enc)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


    def POST(self, code, message):
        #Set up AES cipher
        key = hashlib.sha256(code.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, self.iv)
        #Encrypt code
        code = base64.b64encode(self.iv + cipher.encrypt(self._pad(code)))
        #Encrypt message
        message = base64.b64encode(self.iv + cipher.encrypt(self._pad(message)))
        
        #Update database with encrypted strings
        with sqlite3.connect(DB_STRING) as c:
            c.execute("INSERT INTO data VALUES (?, ?)",
                      [code, message])

def setup_database():
    """
    Create the `user_string` table in the database
    on server startup
    """
    with sqlite3.connect(DB_STRING) as con:
        con.execute("CREATE TABLE data (code, message)")


def cleanup_database():
    """
    Destroy the `data` table from the database
    on server shutdown.
    """
    with sqlite3.connect(DB_STRING) as con:
        con.execute("DROP TABLE data")


if __name__ == '__main__':
    conf = {
        '/': {
            'tools.sessions.on': True,
            'tools.staticdir.root': os.path.abspath(os.getcwd())
        },
        '/retriever': {
            'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
            'tools.response_headers.on': True,
            'tools.response_headers.headers': [('Content-Type', 'text/plain')],
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './public'
        }
    }

    cherrypy.engine.subscribe('start', setup_database)
    cherrypy.engine.subscribe('stop', cleanup_database)

    webapp = StringGenerator()
    webapp.retriever = StringGeneratorWebService()
    cherrypy.config.update({'server.socket_host': '0.0.0.0'})
    cherrypy.quickstart(webapp, '/', conf)
