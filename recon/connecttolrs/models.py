from django.db import models

# Create your models here.
class saved_tokens(models.Model):
	user_id = models.CharField(max_length=100)
	consumer_key = models.CharField(max_length=100)
	access_token = models.CharField(max_length=100)

	def __unicode__(self):
		return "%s for %s<>%s" % (access_token, user_name, consumer_key)