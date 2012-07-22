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

class Unit4_handler(webapp2.RequestHandler):
  def render_str(self, template, **params):
  	template = jinja_env.get_template(template)
  	return template.render(params)
  
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

#h = make_pw_hash('spez', 'hunter2')
#print valid_pw('spez', 'hunter2', h)
#print valid_pw('spez', 'hunter', h)

#----------------------------------------------
# [+] ACCOUNT
#----------------------------------------------

class Hw4Account(Unit4_handler):
	def render_front(self, message = "", cookie_message=""):
		#logging.info("DEBUG: ====>" + "BlogPage.render_front()")
		entries = db.GqlQuery("SELECT * FROM User ORDER BY created DESC LIMIT 10")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		self.render("unit4_account.html", entries=entries, 
		                                  message=message, 
		                                  cookie_message=cookie_message)

	def get(self):
		logging.info("DEBUG: ====>" + "Hw4Account.get()")
		message = ""
		username_cookie      = self.request.cookies.get('user_id', None)
		if username_cookie:
			username = check_secure_val(username_cookie)
			if username:
				logging.info("==> Hw4Account:get() username=" + username)
				message="You are logged in as %s" % username
		cookie_message="cookie=%s, empty=%s" % (username_cookie, 
		                                        str(valid_cookie(username_cookie)))
		self.render_front(message=message, cookie_message=cookie_message)

#----------------------------------------------
# [+] WELCOME
#----------------------------------------------

class Hw4Welcome(Unit4_handler):
  def get(self):
	username_cookie      = self.request.cookies.get('user_id', None)
	if not username_cookie:
		logging.error("==> ##### Hw4Welcome: no username in cookies")
		self.redirect("/unit4_hw_account/signup")
		return

	username = check_secure_val(username_cookie)

	if not username:
		logging.error("==> ##### Hw4Welcome: corrupted username: " + username_cookie)
		self.redirect("/unit4_hw_account/signup")
	else:
		self.response.out.write("Welcome, %s!" % username)
		self.response.out.write("<br><hr>")
		self.response.out.write("<a href='/unit4_hw_account/logout'>Logout</a><br>")
		self.response.out.write("<a href='/unit4_hw_account'>Back</a>")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE    = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
COOKIE_RE   = re.compile(r'.+=; Path=/')

def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)
    
#----------------------------------------------
# [+] SIGNUP
#----------------------------------------------
class Hw4Signup(Unit4_handler):

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
		self.render("unit4_signup.html", username = username,
		                                 email = email,
		                                 username_error = username_error,
		                                 password_error = password_error,
		                                 verify_error = verify_error,
		                                 email_error = email_error)

  def get(self):
		logging.info("DEBUG: ====>" + "Hw4Signup.get()")
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
		logging.info("==> Hw4Signup:post() OK: set cookie to " + make_secure_val(username))
		self.redirect("/unit4_hw_account/welcome")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGIN
#----------------------------------------------

class Hw4Login(Unit4_handler):

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
		self.render("unit4_login.html", username=username,
		                                username_error=username_error,
		                                password_error=password_error)

  def get(self):
		logging.info("DEBUG: ====>" + "Hw4Login.get()")
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
		self.redirect("/unit4_hw_account/welcome")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGOUT
#----------------------------------------------

class Hw4Logout(Unit4_handler):
  def get(self):
	self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	self.redirect("/unit4_hw_account/signup")

app = webapp2.WSGIApplication(
                               [('/unit4_hw_account',         Hw4Account),
                                ('/unit4_hw_account/signup',  Hw4Signup),
                                ('/unit4_hw_account/welcome', Hw4Welcome),
                                ('/unit4_hw_account/login',   Hw4Login),
                                ('/unit4_hw_account/logout',  Hw4Logout)],
                               debug=True)

app.run()

