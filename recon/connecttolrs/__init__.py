from django.conf import settings
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
import requests
import httplib
import hashlib
import time
import oauth.oauth as oauth

_consumers = {}

def get_statements(displaycallback, info, actor=None,object=None,verb=None, consumer=None, token=None):
    # headers = oauth_request.to_header()
    url = "http://localhost:8000/XAPI/statements/"
    if consumer and token: #oauth time
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, http_method='GET', http_url=url)
        headers = oauth_request.to_header()
        # oauth_request.sign_request(signature_method_hmac_sha1, consumer, token)
        # return client.access_resource(oauth_request)
    else:
        auth = "Basic %s" % settings.LRS_BASIC_CREDS
        headers = {"Authorization": auth}
    headers['X-Experience-APIVersion'] = "0.95"
    params = {}
    if actor:
        params['actor'] = actor
    if object:
        params['object'] = object
    if verb:
        params['verb'] = verb
    r = requests.get(url, params=params, headers=headers)
    if r.status_code != 200:
        raise Exception("error getting statements -- %s -- %s" % (r.status_code,r.content))
    # return r.content
    info['d'] = {'stmts':r.content}
    return displaycallback(**info)

def get_consumer(key, secret):
    return oauth.OAuthConsumer(key, secret)   

SERVER = 'http://127.0.0.1'
PORT = '8000'
REQUEST_TOKEN_URL = '/XAPI/OAuth/initiate'
ACCESS_TOKEN_URL = '/XAPI/OAuth/token'
AUTHORIZATION_URL = '/XAPI/OAuth/authorize'
CALLBACK_URL = "%s:%s%s" % ('http://127.0.0.1','8080',reverse('connecttolrs.views.access_token_callback'))

def get_token(token_str):
    return oauth.OAuthToken.from_string(token_str)

def request_token(f, info, consumer):
    # setup
    client = SimpleOAuthClient(SERVER, PORT, REQUEST_TOKEN_URL, ACCESS_TOKEN_URL, AUTHORIZATION_URL)
    signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
    signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()
    req = info['req']
    thekey = hashlib.sha256(consumer.key).hexdigest()[:10]
    _consumers[thekey] = {}
    _consumers[thekey]['consumer'] = consumer
    _consumers[thekey]['info'] = info
    _consumers[thekey]['f'] = f
    _consumers[thekey]['client'] = client

    cburl = "%s?cid=%s" % (CALLBACK_URL, thekey)

    # get request token
    print "__init__: CALLBACK_URL: %s" % CALLBACK_URL
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, callback=cburl, http_url=client.request_token_url)
    oauth_request.sign_request(signature_method_plaintext, consumer, None)
    request_token = client.fetch_request_token(oauth_request)
    print "__init__: done with client.fetch_request_token: %s" % request_token.to_string()
    # return HttpResponse("request token in __init__.py<br/>key: %s<br/>secret: %s<br/>callback ok: %s" % 
    #                                 (request_token.key, request_token.secret, request_token.callback_confirmed))
    
    _consumers[thekey]['token'] = request_token
    # authorize
    oauth_request = oauth.OAuthRequest.from_token_and_callback(token=request_token, http_url=client.authorization_url)
    resp = client.authorize_token(oauth_request)
    print "__init__: doen with client.authorize_token: %s" % resp.content
    import pprint
    pprint.pprint(resp.headers)
    if resp.status_code > 300 and resp.status_code < 400:
        newurl = resp.headers['location']
        print "newurl: %s -- doing a redirect now"
        return HttpResponseRedirect(newurl) 
    if resp.status_code != 200:
        print "Fail: %s" % resp.status_code
        #print r.text
        f = open('/home/ubuntu/Desktop/error.html', 'w')
        f.write(resp.content)
        f.close()
        return HttpResponse("/home/ubuntu/Desktop/error.html")

    import urlparse, cgi
    query = urlparse.urlparse(resp.url)[4]
    params = cgi.parse_qs(query, keep_blank_values=False)
    verifier = params['oauth_verifier'][0]
    print 'verifier: %s' % verifier
    return HttpResponse("hmm... i got a return.. the url had a param called oauth_verifier: %s" % verifier)

def token_callback(req):
    # print "in access_token_callback"
    # import urlparse, cgi
    # query = urlparse.urlparse(req.url)[4]
    # params = cgi.parse_qs(query, keep_blank_values=False)
    verifier = req.GET['oauth_verifier']
    cid = req.GET['cid']
    consumer = _consumers[cid]['consumer']
    f = _consumers[cid]['f']
    info = _consumers[cid]['info']
    token = _consumers[cid]['token']
    client = _consumers[cid]['client']

    signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()

    del _consumers[cid]

    print 'verifier: %s' % verifier
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, token=token, verifier=verifier, http_url=client.access_token_url)
    oauth_request.sign_request(signature_method_plaintext, consumer, token)
    # finally get access token
    token = client.fetch_request_token(oauth_request)
    
    # will wanna do some sort of f(info['req']) call here
    return f(info['req'], token)
    # return HttpResponse("hmm... i got a return.. the url had a param called oauth_verifier: %s" % verifier)

class SimpleOAuthClient(oauth.OAuthClient):

    def __init__(self, server, port=httplib.HTTP_PORT, request_token_url='', access_token_url='', authorization_url=''):
        self.server = server
        self.port = port
        self.request_token_url = "%s:%s%s" % (server, port, request_token_url)
        self.access_token_url = "%s:%s%s" % (server, port, access_token_url)
        self.authorization_url = "%s:%s%s" % (server, port, authorization_url)

    def fetch_request_token(self, oauth_request):
        headers = oauth_request.to_header()
        headers['X-Experience-API-Version'] = "0.95"
        
        response = requests.request(oauth_request.http_method, self.request_token_url, headers=headers)
        
        if response.status_code != 200:
            print "Fail: %s" % response.status_code
            #print r.text
            f = open('/home/ubuntu/Desktop/error.html', 'w')
            f.write(response.content)
            f.close()
            print "text written to /home/user/Desktop/error.html"
        return oauth.OAuthToken.from_string(response.content)

    def fetch_access_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        # print "%s -- http method: %s\nurl: %s\nheaders: %s" % (__name__,oauth_request.http_method, self.access_token_url, oauth_request.to_header())
        self.connection.request(oauth_request.http_method, self.access_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        # if response.status != 200:
        #     print "Fail: %s" % response.status
        #     import pprint
        #     headers = dict(response.getheaders())
        #     pprint.pprint(headers)
        #     #print r.text
        #     f = open('/home/ubuntu/Desktop/error.html', 'w')
        #     f.write(response.read())
        #     f.close()
        #     print "text written to /home/user/Desktop/error.html"
        return oauth.OAuthToken.from_string(response.read())

    def authorize_token(self, oauth_request):
        print oauth_request.http_method
        print oauth_request.to_url()
        return requests.request(oauth_request.http_method, oauth_request.to_url(), allow_redirects=False)
        

    def nocallback_authorize_token(self, oauth_request):
        # via url
        # -> typically just some okay response
        # print "%s -- http method: %s\nurl: %s\n" % (__name__,oauth_request.http_method, oauth_request.to_url())
        self.connection.request(oauth_request.http_method, oauth_request.to_url()) 
        response = self.connection.getresponse()
        if response.status != 200:
            # print "Fail: %s" % response.status
            # print "fail body: %s " % response.read()
            # import pprint
            headers = dict(response.getheaders())
            # pprint.pprint(headers)
            # print "+++++++++++ gonna do the redirect ++++++++++++++"
            newurl = headers['location']
            import urlparse, cgi
            parts = urlparse.urlparse(newurl)[2:]
            
            if response.status > 300 and response.status < 400:
                print parts[2]
                u = urlparse.parse_qs(parts[2])
                return 'http://example.com?oauth_verifier=%s' % raw_input("go to %s, verify, enter PIN here: " % u['next'])
            
            # print parts
            # parts is (path, '', params, '')
            newurl = "%s?%s" % (parts[0],parts[2])
            print "redirect to : %s" % newurl
            self.connection.request('GET', newurl)
            response = self.connection.getresponse()
            # print response.status
            # print response.read()

            # print "---------- next redirect -----------"
            import urllib, urllib2, cookielib

            cj = cookielib.CookieJar()
            opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
            urllib2.install_opener(opener)

            headers = dict(response.getheaders())
            # pprint.pprint(headers)
            newurl = headers['location']
            # parts = urlparse.urlparse(newurl)[2:]
            # print parts
            # # parts is (path, '', params, '')
            # newurl = "%s?%s" % (parts[0],parts[2])
            # print "redirect to : %s" % newurl
            # self.connection.request('GET', newurl)
            # response = self.connection.getresponse()

            response = urllib2.urlopen(newurl)

            # print dir(response)
            # print response.code
            theform = response.read()
            # print theform

            # print "------------- login form -------------"
            headers = {'Content-Type' :'application/x-www-form-urlencoded'}
            # csrfmiddlewaretoken=vOANgRw4XFr7NOG36gnW3IvKC596TCt1&username=tom&password=1234
            # formdata = "csrfmiddlewaretoken=%s&username=%s&password=%s" % (csrf_token,uname,pwd)

            # print "cookies?: %s " % dir(cj)

            token = [x.value for x in cj if x.name == 'csrftoken'][0]
            # print "token: %s" % token
            # print "csrf_token: %s" % csrf_token

            params = urllib.urlencode(dict(username = USER_NAME, password=USER_PWD, csrfmiddlewaretoken=token))
            req = urllib2.Request(newurl, params, headers) 
            req.add_header( 'Referer', newurl )
            try:
                response = urllib2.urlopen(req)
            except urllib2.HTTPError as e:
                print "you got an httperror 167"
                f = open('/home/ubuntu/Desktop/error.html', 'w')
                f.write(e.read())
                f.close()
                print "text written to /home/user/Desktop/error.html"
            # print response.read()


            # self.connection.request('POST', newurl, formdata, headers=headers)
            # print "-------------- end form --------------"
            # response = self.connection.getresponse()
            # print response.code
            # #print r.text
            # f = open('/home/ubuntu/Desktop/error.html', 'w')
            # f.write(response.read())
            # f.close()
            # print "text written to /home/user/Desktop/error.html"
        return response.read()

    def access_resource(self, oauth_request):
        # via post body
        # -> some protected resources
        headers = oauth_request.to_header()
        headers['X-Experience-API-Version']= '0.95'
        self.connection.request('GET', oauth_request.get_normalized_http_url(), headers=headers)
        response = self.connection.getresponse()
        if response.status == 200 or response.status == 204:
            return response.read()
        else:
            f = open('/home/ubuntu/Desktop/error.html', 'w')
            f.write(response.read())
            f.close()
            print "text written to /home/user/Desktop/error.html"