from django.db import models
from django.contrib.auth.models import User

class Tokens(models.Model):
	user = models.ForeignKey(User)
	token_str = models.CharField(max_length=250)