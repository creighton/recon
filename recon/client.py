"""
The MIT License

Copyright (c) 2007 Leah Culver

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Example consumer. This is not recommended for production.
Instead, you'll want to create your own subclass of OAuthClient
or find one that works with your web framework.
"""
"""
tom c changed stuff to work with the ADL LRS
"""

import httplib
import time
import oauth.oauth as oauth

# settings for the local test consumer
SERVER = '127.0.0.1'
PORT = 8000

# fake urls for the test server (matches ones in server.py)
REQUEST_TOKEN_URL = '/XAPI/OAuth/initiate'
ACCESS_TOKEN_URL = '/XAPI/OAuth/token'
AUTHORIZATION_URL = '/XAPI/OAuth/authorize'
CALLBACK_URL = 'oob'
RESOURCE_URL = 'http://127.0.0.1:8000/XAPI/'

# key and secret granted by the service provider for this consumer application - same as the MockOAuthDataStore
CONSUMER_KEY = '<get your own.. register an app on the adllrs>'
CONSUMER_SECRET = '<get your own>'

# user login info.. typically this would be entered by the user during oauth authorize
USER_NAME = "<get your own... register a user on the adllrs>"
USER_PWD = "<get your own>"

# example client using httplib with headers
class SimpleOAuthClient(oauth.OAuthClient):

    def __init__(self, server, port=httplib.HTTP_PORT, request_token_url='', access_token_url='', authorization_url=''):
        self.server = server
        self.port = port
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorization_url = authorization_url
        self.connection = httplib.HTTPConnection("%s:%d" % (self.server, self.port))

    def fetch_request_token(self, oauth_request):
        headers = oauth_request.to_header()
        headers['X-Experience-API-Version'] = "0.95"

        self.connection.request(oauth_request.http_method, self.request_token_url, headers=headers) 
        response = self.connection.getresponse()
        
        return oauth.OAuthToken.from_string(response.read())

    def fetch_access_token(self, oauth_request):
        self.connection.request(oauth_request.http_method, self.access_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        
        return oauth.OAuthToken.from_string(response.read())

    def authorize_token(self, oauth_request):
        self.connection.request(oauth_request.http_method, oauth_request.to_url()[3:]) 
        response = self.connection.getresponse()
        
        # bankin on a redirect
        if response.status != 200:
            if response.status > 300 and response.status < 400:
                headers = dict(response.getheaders())
                newurl = headers['location']
                import urlparse, cgi
                parts = urlparse.urlparse(newurl)[2:]
            
                print parts[2]
                u = urlparse.parse_qs(parts[2])
                return 'http://example.com?oauth_verifier=%s' % raw_input("go to %s, verify, enter PIN here: " % u['next'])
            else:
                raise Exception("something didn't work right\nresponse: %s -- %s" % (response.status, response.read()))
            
        return response.read()

    def access_resource(self, oauth_request):
        headers = oauth_request.to_header()
        headers['X-Experience-API-Version']= '0.95'
        self.connection.request('GET', oauth_request.get_normalized_http_url()[3:], headers=headers)
        response = self.connection.getresponse()
        if response.status == 200 or response.status == 204:
            return response.read()
        else:
            raise Exception("response didn't come back right\nresponse:%s -- %s" % (response.status, response.read()))

def run_example():

    # setup
    print '** OAuth Python Library Example **'
    client = SimpleOAuthClient(SERVER, PORT, REQUEST_TOKEN_URL, ACCESS_TOKEN_URL, AUTHORIZATION_URL)
    consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
    signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
    signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()
    pause()

    # get request token
    print '* Obtain a request token ...'
    pause()
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, callback=CALLBACK_URL, http_url=client.request_token_url)
    oauth_request.sign_request(signature_method_plaintext, consumer, None)
    print 'REQUEST (via headers)'
    pause()
    token = client.fetch_request_token(oauth_request)
    print 'GOT'
    print 'key: %s' % str(token.key)
    print 'secret: %s' % str(token.secret)
    print 'callback confirmed? %s' % str(token.callback_confirmed)
    pause()

    print '* Authorize the request token ...'
    pause()
    oauth_request = oauth.OAuthRequest.from_token_and_callback(token=token, http_url=client.authorization_url)
    print 'REQUEST (via url query string)'
    pause()
    # this will actually occur only on some callback
    # tom c.. 
    # you won't get a response with a verifier param normally
    # you'd either get the param going to your callback url
    # or you'd get an oob "PIN" that you'd manually enter 
    # in the client as the verifier
    response = client.authorize_token(oauth_request)
    print 'GOT'
    print response
    # sad way to get the verifier
    import urlparse, cgi
    query = urlparse.urlparse(response)[4]
    params = cgi.parse_qs(query, keep_blank_values=False)
    verifier = params['oauth_verifier'][0]
    print 'verifier: %s' % verifier
    pause()

    # get access token
    print '* Obtain an access token ...'
    pause()
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, verifier=verifier, http_url=client.access_token_url)
    oauth_request.sign_request(signature_method_plaintext, consumer, token)
    print 'REQUEST (via headers)'
    print 'parameters: %s' % str(oauth_request.parameters)
    pause()
    token = client.fetch_access_token(oauth_request)
    print 'GOT'
    print 'key: %s' % str(token.key)
    print 'secret: %s' % str(token.secret)
    pause()

    # access some protected resources
    print '* Access protected resources ...'
    pause()
    
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, http_method='GET', http_url="/XAPI/statements")
    oauth_request.sign_request(signature_method_hmac_sha1, consumer, token)
    
    print 'REQUEST (via get)'
    print 'parameters: %s' % str(oauth_request.parameters)
    pause()
    
    params = client.access_resource(oauth_request)
    
    print 'GOT'
    print 'non-oauth parameters: %s' % params
    pause()

def pause():
    print ''
    time.sleep(1)

if __name__ == '__main__':
    run_example()
    print 'Done.'
