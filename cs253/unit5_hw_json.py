import webapp2
import cgi
import os
import jinja2
import logging
import urllib
import re
import hmac
import random
import string
import json

import time
import datetime
#from datetime import timedelta
from google.appengine.api import memcache
from google.appengine.ext import db

template_dir =  os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

#----------------------------------------------
# [+] USER
#----------------------------------------------

class User(db.Model):
	username       = db.StringProperty(required = True)
	email          = db.TextProperty()
	password_hash  = db.TextProperty(required = True)
	created        = db.DateTimeProperty(auto_now_add = True)

#----------------------------------------------
# [+] HANDLER
#----------------------------------------------

class MainPageHandler(webapp2.RequestHandler):
  def render_str(self, template, **params):
  	template = jinja_env.get_template(template)
  	return template.render(params)
  
  def render_json(self, text=""):
  	self.response.headers['Content-Type'] = 'application/json'
  	self.response.out.write(text)
  
  def render(self, template, **kw):
  	self.write(self.render_str(template, **kw))

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

#----------------------------------------------
# [+] HASH
#----------------------------------------------

SECRET = "some secure text to make sure not so secure things are in safe"

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(secure_val):
    logging.info("==> check_secure_val: secure_val=%s" % (secure_val))
    val = secure_val.partition("|")[0]
    logging.info("==> check_secure_val: secure_val=%s, val=%s" % (secure_val,val))
    if secure_val == make_secure_val(val):
        return val
    return None

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(10))


def make_password_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    logging.info("==> make_password_hash: n=" + name + " s=" + salt + " p=" + password)
    h = hmac.new(str(name + salt), password).hexdigest()
    return '%s|%s' % (h, salt)

def validate_password(name, password, password_hash):
    s = password_hash.partition("|")
    salt = s[2]
    if make_password_hash(name, password, salt) == password_hash:
        return True
    return False

def format_date_for_json(dt):
	# Wed May  2 10:33:55 2012
	return dt.strftime("%a %b %d %H:%M:%S %Y")

#----------------------------------------------
# [+] ACCOUNT
#----------------------------------------------

class BlogAccount(MainPageHandler):
	def render_front(self, template, **kw):
		#logging.info("DEBUG: ====>" + "BlogPage.render_front()")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		message = ""
		username_cookie      = self.request.cookies.get('user_id', None)
		#logging.info("==> BlogAccount:render_front() cookie=" + username_cookie)
		if username_cookie:
			username = check_secure_val(username_cookie)
			if username:
				logging.info("==> BlogAccount:render_front() username=" + username)
				message="Logged in as %s" % username
		cookie_message="cookie=%s, empty=%s" % (username_cookie, 
		                                        str(valid_cookie(username_cookie)))

		self.render(template, message=message, cookie_message=cookie_message, **kw)

#----------------------------------------------
# [+] USERS
#----------------------------------------------

class BlogUsers(BlogAccount):

	def get(self):
		logging.info("DEBUG: ====>" + "BlogAccount.get()")
		entries = db.GqlQuery("SELECT * FROM User ORDER BY created DESC LIMIT 10")
		self.render_front("unit5_json.html", entries=entries)

#----------------------------------------------
# [+] WELCOME
#----------------------------------------------

class BlogWelcome(BlogAccount):
  def get(self):
	username_cookie      = self.request.cookies.get('user_id', None)
	if not username_cookie:
		logging.error("==> ##### BlogWelcome: no username in cookies")
		self.redirect("/unit5_hw_json/signup")
		return

	username = check_secure_val(username_cookie)

	if not username:
		logging.error("==> ##### BlogWelcome: corrupted username: " + username_cookie)
		self.redirect("/unit5_hw_json/signup")
	else:
		self.render_front("unit5_welcome.html", username=username)


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE    = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
COOKIE_RE   = re.compile(r'.+=; Path=/')

def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)
    
#----------------------------------------------
# [+] SIGNUP
#----------------------------------------------
class BlogSignup(MainPageHandler):

  def valid_username(self, username):
  	if not username:
		return "Username is not specified" 
  	if not USERNAME_RE.match(username):
		return "Username is not valid" 
	q = User.gql("WHERE username = :1", username)
	result = q.get()
	if result:
		return "Username is used"
	return ""

  def valid_password(self, val):
	if not val:
		return "Password is not specified" 
	if not (PASSWORD_RE.match(val)):
		return "Password is not valid"
	return ""

  def valid_verify(self, val, verify):
	if not val:
		return "Password verification is not specified" 
	if val != verify:
		return "Passwords are not identical"
	return ""

  def valid_email(self, val):
	if val:
		if not EMAIL_RE.match(val):
			return "This is not a valid e-mail"
	return ""

  def render_front(self, username="", email="", 
                       username_error="", password_error="", 
		               verify_error="", email_error=""):
		#logging.info("DEBUG: ====>" + "BlogPage.render_front()")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		self.render("unit5_signup.html", username = username,
		                                 email = email,
		                                 username_error = username_error,
		                                 password_error = password_error,
		                                 verify_error = verify_error,
		                                 email_error = email_error)

  def get(self):
		logging.info("DEBUG: ====>" + "BlogSignup.get()")
		self.render_front()

  def post(self):
	username = self.request.get("username")
	password = self.request.get("password")
	verify   = self.request.get("verify")
	email    = self.request.get("email")

	username_check = self.valid_username(username)
	password_check = self.valid_password(password)
	verify_check   = self.valid_verify(password, verify)
	email_check    = self.valid_email(email)

	#self.response.out.write("==>"+username_check +"::"+ password_check +"::"+ verify_check +"::"+ email_check)

	if username_check != "" or password_check != "" or verify_check != "" or email_check != "":
		self.render_front(username, email, 
		                  username_check, password_check, 
		                  verify_check, email_check)
	else:
		password_hash=make_password_hash(username, password)
		a = User(username=username, email=email, password_hash=password_hash)
		a.put()
		self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(username))
		logging.info("==> BlogSignup:post() OK: set cookie to " + make_secure_val(username))
		self.redirect("/unit5_hw_json/welcome")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGIN
#----------------------------------------------

class BlogLogin(MainPageHandler):

  def valid_username(self, username):
  	if not username:
		return "Username is not specified" 
  	if not USERNAME_RE.match(username):
		return "Username is not valid"

	#user = GqlQuery("SELECT * FROM User WHERE username=:1", username  )
	q = User.gql("WHERE username = :1", username)
	result = q.get()
	if not result:
		return "Username is unknown"
	
	return ""

  def valid_password(self, password, username):
	if not password:
		return "Password is not specified" 
	if not (PASSWORD_RE.match(password)):
		return "Password is not valid"

	if not username:
		return ""

	q = User.gql("WHERE username = :1", username)
	user = q.get()
	if not user:
		return ""
	if not validate_password(username, password, user.password_hash):
		return "Password is wrong"

	return ""

  def render_front(self, username="", 
                       username_error="", password_error=""):
		#logging.info("DEBUG: ====>" + "BlogPage.render_front()")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		self.render("unit5_login.html", username=username,
		                                username_error=username_error,
		                                password_error=password_error)

  def get(self):
		logging.info("DEBUG: ====>" + "BlogLogin.get()")
		self.render_front()

  def post(self):
	username = self.request.get("username")
	password = self.request.get("password")

	username_check = self.valid_username(username)
	password_check = self.valid_password(password, username)

	#self.response.out.write("==>"+username_check +"::"+ password_check +"::"+ verify_check +"::"+ email_check)

	if username_check != "" or password_check != "":
		self.render_front(username, username_check, password_check)
	else:
		self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(username))
		self.redirect("/unit5_hw_json/welcome")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGOUT
#----------------------------------------------

class BlogLogout(MainPageHandler):
  def get(self):
	self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	self.redirect("/unit5_hw_json/signup")

#----------------------------------------------
# [+] BLOG
#----------------------------------------------


class BlogEntry(db.Model):
	title     = db.StringProperty(required = True)
	body      = db.TextProperty(required = True)
	created   = db.DateTimeProperty(auto_now_add = True)

class BlogPage(BlogAccount):
	def get(self, j=None):
		#logging.info("DEBUG: ====>" + "BlogPage.get(): json=<%s>" % j)
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		#logging.info("DEBUG: ====>" + "BlogPage.get()")
		key = "top"
		data = memcache.get(key)
		cache_age=0
		if data is None:
			logging.error("DB QUERY")
			entries = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC LIMIT 10")
			memcache.set(key, (entries, datetime.datetime.now()))
		else:
			entries, saving_time = data[0], data[1]
			logging.error("used CACHE with key=" + key)
			diff = datetime.datetime.now() - saving_time
			cache_age = diff.seconds
		cache_age_message = "Queried %s seconds ago" % cache_age
		if not j:
			self.render_front("unit5_blog.html", entries=entries, cache_age_message=cache_age_message)
		else:
			r = []
			for e in entries:
				debug = db.to_dict(e)
				logging.info("DEBUG: ====>" + str(debug) + " ::: ")
				tmp = {}
				tmp["id"]      = e.key().id()
				tmp["content"] = debug["body"] 
				tmp["subject"] = debug["title"]
				tmp["created"]      = format_date_for_json(debug["created"])
				tmp["last_modified"] = format_date_for_json(debug["created"])
				r.append(tmp)
			self.render_json(json.dumps(r))
			

class BlogNewEntry(BlogAccount):
	def get(self):
		self.render_front("unit5_blog_new_entry.html")
		
	def post(self):
		title = self.request.get("subject")
		body  = self.request.get("content")
		if title and body:
			a = BlogEntry(title=title, body=body)
			a.put()
			#logging.info("DEBUG: ====>" + str(db.to_dict(a)) + " ::: " + str(a.key().id()))
			memcache.delete('top')
			self.redirect("/unit5_hw_json/" + str(a.key().id()))
		else:
			error = "we need both subject and content!"
			self.render_front("unit5_blog_new_entry.html", title=title, body=body, error=error)

class BlogOneEntry(BlogAccount):
		
	def get(self, entryId, j=None):
		entryId = int(urllib.unquote(entryId))
		logging.info("DEBUG: ====>" + str(entryId) +" <<")
		key = "entry#%s" % entryId
		data = memcache.get(key)
		cache_age=0
		if data is None:
			logging.error("DB QUERY")
			entry = BlogEntry.get_by_id(entryId)
			if entry:
				memcache.set(key, (entry, datetime.datetime.now()))
		else:
			entry, saving_time = data[0], data[1]
			logging.error("used CACHE with key=" + key)
			diff = datetime.datetime.now() - saving_time
			cache_age = diff.seconds
		cache_age_message = "Queried %s seconds ago" % cache_age

		if not entry:
			self.render_front("unit5_blog_one_entry.html", error="Blog entry " + str(entryId) + " doesn't exist!", cache_age_message=cache_age_message)
		elif not j:
			self.render_front("unit5_blog_one_entry.html", error="", entry=entry, cache_age_message=cache_age_message)
		else:
			tmp = {}
			tmp["id"]      = entry.key().id()
			tmp["content"] = entry.body 
			tmp["subject"] = entry.title
			tmp["created"]      = format_date_for_json(entry.created)
			tmp["last_modified"] = format_date_for_json(entry.created)
			self.render_json(json.dumps(tmp))

#----------------------------------------------
# [+] FLUSH CACHE
#----------------------------------------------

class BlogFlushCache(MainPageHandler):
  def get(self):
	memcache.flush_all()
	self.redirect("/unit5_hw_json")


#----------------------------------------------
# [+] ROUTING
#----------------------------------------------

app = webapp2.WSGIApplication(
                               [],
                               debug=True)


app = webapp2.WSGIApplication(
                               [('/unit5_hw_json(/?\.json)?', 		   BlogPage),
                                ('/unit5_hw_json/users',    		   BlogUsers),
                                ('/unit5_hw_json/signup',   		   BlogSignup),
                                ('/unit5_hw_json/welcome',             BlogWelcome),
                                ('/unit5_hw_json/login',               BlogLogin),
                                ('/unit5_hw_json/logout',              BlogLogout),
                                ('/unit5_hw_json/flush',               BlogFlushCache),
                                ('/unit5_hw_json/([0-9]+)(/?\.json)?', BlogOneEntry),
                                ('/unit5_hw_json/newpost',  		   BlogNewEntry)],
                               debug=True)

app.run()

