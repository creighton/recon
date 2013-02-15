from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, render_to_response
from report.models import Tokens
import connecttolrs

# Client Name: recon app 
# Client Identifier: 1caabcc0f6154c1786f370f101d0d6f5 
# Client Shared-Secret: 6FUAtfwRVw
KEY = "7e29e09998644b32b4872e97a36f72ec"
SECRET = "CS6GzuF23M"

# of course you wouldn't really do this
TESTUSER = {'name':'tom', 'email':'tom@example.com', 'password':'1234'}

def home(req):
    info = {'req': req, 'page': 'report/home.html'}
    return connecttolrs.get_statements(display, info, verb="http://adlnet.gov/xapi/verbs/completed")
    # return render(req, 'report/home.html', {"stmts":None, "msg":"this sucks"})

def oauth_stmts(req, access_token=None):
    #
    #  START HERE::: trying to figure out how to make this work w/o report knowing about oauth
    #   just added display and info to get_statements...  
    #
    info = {'req': req, 'page': 'report/home.html'}
    try:
        user = User.objects.get(username__exact=TESTUSER['name'])
    except User.DoesNotExist:
        user = User.objects.create_user(TESTUSER['name'], TESTUSER['email'], TESTUSER['password'])
    
    consumer = connecttolrs.get_consumer(KEY, SECRET)

    try:
        if access_token:
            token = access_token
        else:
            token = connecttolrs.get_token(Tokens.objects.get(user=user))
        return connecttolrs.get_statements(display, info, consumer=consumer, token=token)
    except Tokens.DoesNotExist:
        print 'token doesn\'t exist'
        return connecttolrs.request_token(oauth_stmts, info, consumer)

def display(**kwargs):
    try:
        req = kwargs['req']
        d = kwargs['d']
        page = kwargs['page']
    except Exception as fail:
        HttpResponseBadRequest(fail)

    return render(req, page, d)