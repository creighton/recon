from django.shortcuts import render, render_to_response
from django.http import HttpResponse
import connecttolrs

def home(req):
    try:
        stmts = connecttolrs.get_statements(verb="http://adlnet.gov/xapi/verbs/completed")
        return render(req, 'report/home.html', {"stmts":stmts})
    except Exception as fail:
        return render(req, 'report/home.html', {"stmts": None, "msg": fail})