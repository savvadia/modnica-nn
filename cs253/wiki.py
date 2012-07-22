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
from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.api import datastore

template_dir =  os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

#----------------------------------------------
# [+] Models
#----------------------------------------------

class User(db.Model):
	username       = db.StringProperty(required = True)
	email          = db.TextProperty()
	password_hash  = db.TextProperty(required = True)
	created        = db.DateTimeProperty(auto_now_add = True)

class WikiEntry(db.Model):
	page_path      = db.StringProperty(required = True)
	wiki_title     = db.StringProperty(required = True)
	wiki_body  	   = db.TextProperty(required = True)
	created        = db.DateTimeProperty(auto_now_add = True)
	createdBy      = db.TextProperty(required = True)

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
# [+] Utils
#----------------------------------------------

SECRET = "some secure text to make sure not so secure things are in safe"

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(secure_val):
    #logging.info("==> check_secure_val: secure_val=%s" % (secure_val))
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

def show_query(query):
    """
    Represent a query as a string
    Based on http://kupuguy.googlecode.com/svn/trunk/appengine-doctests/showquery.py
    """
    from google.appengine.api import datastore

    kind = query._model_class.kind()
    ancestor = query._Query__ancestor
    filters = query._Query__query_sets[0]
    orderings = query._Query__orderings

    res = ["%s.all()" % kind]
    if ancestor is not None:
        res.append("ancestor(%r)" % ancestor)
    for k in sorted(filters):
        res.append("filter(%r, %r)" % (k, filters[k]))
    for p, o in orderings:
        if o==datastore.Query.DESCENDING:
            p = '-'+p
        res.append("order(%r)" % p)

    return '.'.join(res)
#----------------------------------------------
# [+] ACCOUNT
#----------------------------------------------
class WikiAccount(MainPageHandler):
	def getCurrentUsername(self):
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		username_cookie      = self.request.cookies.get('user_id', None)
		#logging.info("==> WikiAccount:render_front() cookie=" + username_cookie)
		if username_cookie:
			username = check_secure_val(username_cookie)
			if username:
				return username
		return None

	def render_front(self, template, cache_age_message="Page is not cached", **kw):
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		logged_as_msg = ""
		username_cookie = self.request.cookies.get('user_id', None)
		username = self.getCurrentUsername()
		if username:
			#logging.info("==> WikiAccount:render_front() username=" + username)
			logged_as_msg="Logged in as %s" % username
		cookie_message="cookie=%s, empty=%s" % (username_cookie, 
		                                        str(valid_cookie(username_cookie)))

		self.render(template, logged_as_msg=logged_as_msg, 
		                      cache_age_message=cache_age_message,
		                      cookie_message=cookie_message, **kw)

#----------------------------------------------
# [+] USERS
#----------------------------------------------

class WikiUsers(WikiAccount):

	def get(self):
		logging.info("DEBUG: ====>" + "WikiAccount.get()")
		entries = db.GqlQuery("SELECT * FROM User ORDER BY created DESC LIMIT 10")
		self.render_front("unit5_json.html", entries=entries)


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE    = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
COOKIE_RE   = re.compile(r'.+=; Path=/')

def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)
    
#----------------------------------------------
# [+] SIGNUP
#----------------------------------------------
class WikiSignup(MainPageHandler):

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
		logging.info("DEBUG: ====>" + "WikiSignup.get()")
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
		logging.info("==> WikiSignup:post() OK: set cookie to " + make_secure_val(username))
		self.redirect("/wiki")


#----------------------------------------------
# [+] LOGIN
#----------------------------------------------

class WikiLogin(MainPageHandler):

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
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		self.render("unit5_login.html", username=username,
		                                username_error=username_error,
		                                password_error=password_error)

  def get(self):
		logging.info("DEBUG: ====>" + "WikiLogin.get()")
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
		self.redirect("/wiki")

#----------------------------------------------
# [+] LOGOUT
#----------------------------------------------

class WikiLogout(MainPageHandler):
  def get(self):
	self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	self.redirect("/wiki/signup")

#----------------------------------------------
# [+] WIKI
#----------------------------------------------
def getFromCacheOrDb(key, page_path, page_id = None):
	data = memcache.get(key)
	cache_age=0
	entry = None

	if data is None:
		if page_id:
			logging.error("DB QUERY: get_by_id()")
			entry = WikiEntry.get_by_id(int(page_id))
		else:
			query = WikiEntry.all()
			query.filter("page_path =", page_path)
			query.order("-created")
			logging.error("DB QUERY: " + show_query(query))
			entries = query.fetch(1)
			if entries:
				entry = entries[0]
		if entry:
			memcache.set(key, (entry, datetime.datetime.now()))
			logging.error("stored CACHE for " + key)
	else:
		entry, saving_time = data[0], data[1]
		logging.error("used CACHE with key=" + key)
		diff = datetime.datetime.now() - saving_time
		cache_age = diff.seconds
	cache_age_message = "Queried %s seconds ago" % cache_age
	return entry, cache_age_message

def getFromCacheOrDbList(key, page_path):
	data = memcache.get(key)
	cache_age=0
	entries = None

	if data is None:
		query = WikiEntry.all()
		query.filter("page_path =", page_path)
		query.order("-created")
		logging.error("DB QUERY: " + show_query(query))
		entries = query.fetch(20)
		if entries:
			memcache.set(key, (entries, datetime.datetime.now()))
			logging.error("stored CACHE for " + key)
	else:
		entries, saving_time = data[0], data[1]
		logging.error("used CACHE with key=" + key)
		diff = datetime.datetime.now() - saving_time
		cache_age = diff.seconds
	cache_age_message = "Queried %s seconds ago" % cache_age
	return entries, cache_age_message

def saveRecord(page_path, obj):
	obj.put()
	logging.error("DB QUERY: SAVED " + repr(obj))
	#logging.info("DEBUG: ====>" + str(db.to_dict(a)) + " ::: " + str(a.key().id()))
	memcache.delete("page-"  + page_path)
	memcache.delete("page--" + page_path)
	memcache.delete("page-"  + page_path+"-history")
	logging.error("cleared CACHE for " + "page-"  + page_path)
	logging.error("cleared CACHE for " + "page--" + page_path)
	logging.error("cleared CACHE for " + "page-"  + page_path+"-history")

class MainPage(WikiAccount):
	def get(self):
		self.redirect("/wiki/Main")

class WikiPage(WikiAccount):
	def get(self, page_id, page_path):
		#logging.info("DEBUG: ====>" + "WikiPage.get(): json=<%s>" % j)
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		#logging.info("DEBUG: ====>" + "WikiPage.get()")
		logging.info("DEBUG: ====> WikiPage.get(): <"+ page_id +"><"+ page_path + ">")
		if not page_id:
			logging.error("ID is not given")
		key = "page-"+page_id+"-"+page_path
		wiki_entry, cache_age_message = getFromCacheOrDb(key, page_path, page_id)
		if not wiki_entry:
			logging.error("=> not found " + page_path + "; redirecting to EDIT it")
			self.redirect("/wiki/_edit" + page_path)
			return
		logging.error("page found:" + page_path)
		self.render_front("wiki_view.html", wiki_entry=wiki_entry, page_path=page_path, cache_age_message=cache_age_message)

class WikiHistory(WikiAccount):
	def get(self, page_path):
		#logging.info("DEBUG: ====>" + "WikiHistory.get(): json=<%s>" % j)
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		key = "page-"+page_path+"-history"
		
		entries, cache_age_message = getFromCacheOrDbList(key, page_path)
		if not entries:
			logging.error("=> not found" + page_path + "; redirecting to EDIT it")
			self.redirect("/wiki/_edit" + page_path)
			return
		logging.error("page found:" + page_path)
		self.render_front("wiki_history.html", entries=entries, page_path=page_path, cache_age_message=cache_age_message)


class WikiEdit(WikiAccount):
	def get(self, page_id, page_path):
		username = self.getCurrentUsername()
		if not username:
			self.redirect("/wiki/login")
			return
		key = "page-"+page_id+"-"+page_path
		wiki_title = self.request.get("wiki_title")
		wiki_body  = self.request.get("content")
		created    = ""
		createdBy  = ""
		logging.error("FIXME: " +wiki_title+"/"+wiki_body+" >> "+page_id+page_path)
		if not wiki_title or not wiki_body:
			wiki_title = page_path
			wiki_entry, cache_age_message = getFromCacheOrDb(key, page_path, page_id)
			if wiki_entry:
				wiki_title = wiki_entry.wiki_title
				wiki_body  = wiki_entry.wiki_body
				created    = wiki_entry.created
				createdBy  = wiki_entry.createdBy
				logging.error("prepared for page update:" + page_id + page_path)
		self.render_front("wiki_form.html", wiki_title=wiki_title, wiki_body=wiki_body,
		                                    created=created, createdBy=createdBy)
		
	def post(self, page_id, page_path):
		username = self.getCurrentUsername()
		if not username:
			self.redirect("/wiki/login")
			return
		wiki_title = self.request.get("wiki_title")
		wiki_body  = self.request.get("content")
		if not wiki_title:
			wiki_title = page_path
		if wiki_body:
			a = WikiEntry(wiki_title=wiki_title, wiki_body=wiki_body, page_path=page_path, createdBy=username)
			saveRecord(page_path, a)
			self.redirect("/wiki" + page_path)
		else:
			error = "we need both title and body!"
			self.render_front("wiki_form.html", wiki_title=wiki_title, wiki_body=wiki_body)

#----------------------------------------------
# [+] FLUSH CACHE
#----------------------------------------------

class WikiFlushCache(MainPageHandler):
  def get(self):
	memcache.flush_all()
	self.redirect("/wiki")

#----------------------------------------------
# [+] ROUTING
#----------------------------------------------

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication(
                               [
                                ('/wiki', 	              		   MainPage),
                                ('/wiki/flush',    	 	  		   WikiFlushCache),
                                ('/wiki/users',    	 	  		   WikiUsers),
                                ('/wiki/signup',    	  		   WikiSignup),
                                ('/wiki/login',           		   WikiLogin),
                                ('/wiki/logout',          		   WikiLogout),
                                ('/wiki/_history'       + PAGE_RE, WikiHistory),
                                ('/wiki/_edit/?([0-9]*)'+ PAGE_RE, WikiEdit),
                                ('/wiki/?([0-9]*)'      + PAGE_RE, WikiPage),
                               ],
                               debug=True)


app.run()

