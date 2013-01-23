from django.conf import settings
import requests

def get_statements(actor=None,object=None,verb=None):
    auth = "Basic %s" % settings.LRS_BASIC_CREDS
    headers = {"X-Experience-APIVersion":"0.95", "Authorization": auth}
    params = {}
    if actor:
        params['actor'] = actor
    if object:
        params['object'] = object
    if verb:
        params['verb'] = verb
    r = requests.get("http://localhost:8000/XAPI/statements/", params=params, headers=headers)
    if r.status_code != 200:
        raise Exception("error getting statements -- %s -- %s" % (r.status_code,r.content))
    return r.content