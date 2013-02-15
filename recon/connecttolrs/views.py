from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
import requests
import json
import pprint
import connecttolrs

def home(req):
    # username: recon, password: recon
    headers = {"Accept":"application/json"}
    # r = requests.get("http://localhost:8000/XAPI/", headers=headers)
    # make call to lrs
    home_endpoint = "/XAPI/"
    url = "%s%s" % (settings.LRS_ROOT_URL, home_endpoint)
    r = requests.get(url, headers=headers, verify=False)
    print settings.LRS_ROOT_URL
    return HttpResponse(r.content, content_type="application/json")

def access_token_callback(req):
    return connecttolrs.token_callback(req)
    