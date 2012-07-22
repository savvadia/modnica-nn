import os
import webapp2
import jinja2
import json
import urllib2
import logging
import re
import hmac
import random
import string
import json

from xml.dom import minidom
from google.appengine.api import memcache
from google.appengine.ext import db

template_dir =  os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

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
# [+] USER
#----------------------------------------------

class User(db.Model):
	username       = db.StringProperty(required = True)
	email          = db.TextProperty()
	password_hash  = db.TextProperty(required = True)
	created        = db.DateTimeProperty(auto_now_add = True)

#----------------------------------------------
# [+] HASH
#----------------------------------------------

SECRET = "some secure text to make sure not so secure things are in safe"

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(secure_val):
    #logging.info("==> check_secure_val: secure_val=%s" % (secure_val))
    val = secure_val.partition("|")[0]
    val = secure_val.partition("|")[0]
    #logging.info("==> check_secure_val: secure_val=%s, val=%s" % (secure_val,val))
    if secure_val == make_secure_val(val):
        return val
    return None

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(10))


def make_password_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    #logging.info("==> make_password_hash: n=" + name + " s=" + salt + " p=" + password)
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

class ModnicaAccount(MainPageHandler):
	def render_front(self, template, **kw):
		#logging.info("DEBUG: ====>" + "ModnicaPage.render_front()")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		message = ""
		username_cookie      = self.request.cookies.get('user_id', None)
		#logging.info("==> ModnicaAccount:render_front() cookie=" + str(username_cookie))
		if username_cookie:
			username = check_secure_val(username_cookie)
			if username:
				logging.info("==> ModnicaAccount:render_front() username=" + username)
				message="Logged in as %s" % username
		cookie_message="cookie=%s, empty=%s" % (username_cookie, 
		                                        str(valid_cookie(username_cookie)))

		self.render(template, message=message, cookie_message=cookie_message, **kw)


#----------------------------------------------
# [+] USERS
#----------------------------------------------

class ModnicaUsers(ModnicaAccount):

	def get(self):
		logging.info("DEBUG: ====>" + "ModnicaAccount.get()")
		entries = db.GqlQuery("SELECT * FROM User ORDER BY created DESC LIMIT 10")
		self.render_front("unit5_json.html", entries=entries)


#----------------------------------------------
# [+] WELCOME
#----------------------------------------------

class ModnicaWelcome(ModnicaAccount):
  def get(self):
	username_cookie      = self.request.cookies.get('user_id', None)
	if not username_cookie:
		logging.error("==> ##### ModnicaWelcome: no username in cookies")
		self.redirect("/unit6_ascii_w_cache/signup")
		return

	username = check_secure_val(username_cookie)

	if not username:
		logging.error("==> ##### ModnicaWelcome: corrupted username: " + username_cookie)
		self.redirect("/unit6_ascii_w_cache/signup")
	else:
		self.render_front("unit6_welcome.html", username=username)


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE    = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
COOKIE_RE   = re.compile(r'.+=; Path=/')

def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)
    
#----------------------------------------------
# [+] SIGNUP
#----------------------------------------------
class ModnicaSignup(MainPageHandler):

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
		#logging.info("DEBUG: ====>" + "ModnicaPage.render_front()")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		self.render("unit6_signup.html", username = username,
		                                 email = email,
		                                 username_error = username_error,
		                                 password_error = password_error,
		                                 verify_error = verify_error,
		                                 email_error = email_error)

  def get(self):
		logging.info("DEBUG: ====>" + "ModnicaSignup.get()")
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
		logging.info("==> ModnicaSignup:post() OK: set cookie to " + make_secure_val(username))
		self.redirect("/unit6_ascii_w_cache/welcome")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGIN
#----------------------------------------------

class ModnicaLogin(MainPageHandler):

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
		#logging.info("DEBUG: ====>" + "ModnicaPage.render_front()")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		self.render("unit6_login.html", username=username,
		                                username_error=username_error,
		                                password_error=password_error)

  def get(self):
		logging.info("DEBUG: ====>" + "ModnicaLogin.get()")
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
		self.redirect("/unit6_ascii_w_cache/welcome")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGOUT
#----------------------------------------------

class ModnicaLogout(MainPageHandler):
  def get(self):
	self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	self.redirect("/unit6_ascii_w_cache/signup")

#----------------------------------------------
# [+] MAP
#----------------------------------------------

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
	#ip="4.2.2.2"
	ip="212.67.0.1"
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return
	if content:
		d = minidom.parseString(content)
		coords = d.getElementsByTagName("gml:coordinates")
		if coords and coords[0].childNodes[0].nodeValue:
		    lon, lat = coords[0].childNodes[0].nodeValue.split(',')
		    return db.GeoPt(lat, lon)

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

def gmaps_img(points):
    return GMAPS_URL + '&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)

#----------------------------------------------
# [+] ASCII CHAN ARTS
#----------------------------------------------

class Art(db.Model):
	title   = db.StringProperty(required = True)
	art     = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords  = db.GeoPtProperty()

def top_arts(update = False):
	key = 'top'
	arts = memcache.get(key)
	if arts is None or update: 
		logging.error("DB QUERY")
		arts = db.GqlQuery("SELECT * FROM Art "
						   "ORDER BY created DESC "
						   "LIMIT 10")
		# prevent the runnning of multiple queries
		arts = list(arts)
		memcache.set(key, arts)
	else:
		logging.error("used CACHE with key=" + key)
	return arts

class AsciiPage(ModnicaAccount):
	def render_form(self, title="", art="", error=""):
		arts = top_arts()
		img_url = None
		points = filter(None, (a.coords for a in arts))
		if points:
			img_url = gmaps_img(points)
		
		self.render_front("unit6_ascii_form.html", title=title, art=art, error=error, arts=arts, img_url=img_url)

	def get(self):
		logging.info(repr(get_coords(self.request.remote_addr)))
		self.render_form()
		
	def post(self):
		title = self.request.get("title")
		art   = self.request.get("art")
		if title and art:
			a = Art(title=title,art=art)
			coords = get_coords(self.request.remote_addr)
			if coords:
				a.coords = coords
			a.put()
			memcache.flush_all()
			
			self.redirect("/unit6_ascii_w_cache")
		else:
			error = "we need both title and artwork!"
			self.render_form(title, art, error)

#----------------------------------------------
# [+] ROUTING
#----------------------------------------------

app = webapp2.WSGIApplication(
                               [
                                ('/unit6_ascii_w_cache', 	            AsciiPage),
                                ('/unit6_ascii_w_cache/users',    		ModnicaUsers),
                                ('/unit6_ascii_w_cache/signup',   		ModnicaSignup),
                                ('/unit6_ascii_w_cache/welcome',        ModnicaWelcome),
                                ('/unit6_ascii_w_cache/login',          ModnicaLogin),
                                ('/unit6_ascii_w_cache/logout',         ModnicaLogout)
                                ],
                               debug=True)


app.run()

