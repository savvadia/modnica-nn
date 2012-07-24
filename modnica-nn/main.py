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
import datetime

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
	def render_front(self, template, cache_age_message="Page is not cached", **kw):
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

		self.render(template, message=message, cookie_message=cookie_message, cache_age_message=cache_age_message, **kw)

	def getCurrentUsername(self):
		#logging.info("DEBUG: ====>" + "WikiPage.render_front()")
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
	
	# returns one entry and text message about cache age
	def getDbEntry(self, key, query):
		if not key:
			logging.error("getDbEntry(): WARNING: no key is provided")
		else:
			data = memcache.get(key)[0]
			entry, saving_time = data[0], data[1]
			if entry:
				logging.error("used CACHE with key=" + key)
				diff = datetime.datetime.now() - saving_time
				cache_age_message = "Queried %s seconds ago" % diff.seconds
				return entry, cache_age_message
		
		if not query:
			logging.error("getDbEntry(): ERROR: no query is provided, key=" + key)
			return None, "not cached"
			
		entries = query.fetch(1)
		if not entries:
			logging.error("getDbEntry(): ERROR: query returned no data, key=" + key)
			return None, "not cached"
			
		entry = entries[0]
		memcache.set(key, (entry, datetime.datetime.now()))
		logging.error("stored CACHE for " + key)
		return entry, "not cached"
		
	# returns one entry and text message about cache age
	def getDbEntries(self, key, query, noOfEntries = 100):
		if not key:
			logging.error("getDbEntries(): WARNING: no key is provided")
		else:
			data = memcache.get(key)
			if data:
				entries, saving_time = data[0], data[1]
				logging.error("used CACHE with key=" + key)
				diff = datetime.datetime.now() - saving_time
				cache_age_message = "Queried %s seconds ago" % diff.seconds
				return entries, cache_age_message
		
		if not query:
			logging.error("getDbEntries(): ERROR: no query is provided, key=" + key)
			return None, "not cached"
			
		logging.error("DB QUERY: " + show_query(query))
		entries = query.fetch(noOfEntries)
		if not entries:
			logging.error("getDbEntries(): ERROR: query returned no data, key=" + key)
			return None, "not cached"
			
		memcache.set(key, (entries, datetime.datetime.now()))
		logging.error("stored CACHE for " + key)
		return entries, "not cached"

	def saveObj(obj, keyList = {}):
		obj.put()
		logging.error("DB QUERY: SAVED " + repr(obj))
		#logging.info("DEBUG: ====>" + str(db.to_dict(a)) + " ::: " + str(a.key().id()))
		for key in keyList:
			memcache.delete(key)
			logging.error("cleared CACHE for " + key)

#----------------------------------------------
# [+] USERS
#----------------------------------------------

class ModnicaUsers(ModnicaAccount):

	def get(self):
		logging.error("DB QUERY :: SELECT * FROM User")
		entries = db.GqlQuery("SELECT * FROM User ORDER BY created DESC LIMIT 100")
		self.render_front("users.html", entries=entries)

	def post(self):
		logging.info("ModnicaUsers:post(): ====>" + str(self.request) + " ::: ")
		
		userId  = self.request.get("user-id")
		isAdmin = self.request.get("user-isAdmin")
		user = User.get_by_id(int(userId))
		if user:
			user.isAdmin = bool(isAdmin)
			logging.info("DEBUG: ====> isAdmin=" + isAdmin)
			user.put()
			memcache.flush_all()

		self.redirect("/users")

#----------------------------------------------
# [+] ARTICLES
#----------------------------------------------

class ModnicaArticles(ModnicaAccount):

	def get(self):
		query = Article.all()
		query.filter("isLatest =", True)
		query.order("title")
		logging.error("DB QUERY: " + show_query(query))
		entries = query.fetch(100)
		self.render_front("articles.html", entries=entries)

	def post(self):
		logging.info("ModnicaUsers:post(): ====>" + str(self.request) + " ::: ")
		logging.info("ModnicaUsers:post(): ====>" + str(self.request.params) + " ::: ")
		
		articleId  = self.request.get("article-isMain")
		isMain     = self.request.get("article-isMain")

		articles  = Article.all().filter("isMain", True).fetch(1)
		if articles:
			for article in articles:
				if article.key().id() != articleId:
					article.isMain = False
					logging.info("DEBUG: ====> clearing isMain for " + str(article.key().id()))
					article.put()
		
		if (not article) or (article.key().id() != articleId):
			article    = Article.get_by_id(int(articleId))
			if article:
				article.isMain = bool(isMain)
				logging.info("DEBUG: ====> setting isMain=" + str(isMain) + " for " + str(articleId))
				article.put()
		memcache.flush_all()

		self.redirect("/articles")

class ModnicaArticlesVersions(ModnicaAccount):

	def get(self, pagePath):
		query = Article.all()
		query.filter("pagePath =", pagePath)
		query.order("-created")
		logging.error("DB QUERY: " + show_query(query))
		entries = query.fetch(100)
		self.render_front("articles_versions.html", entries=entries)

	def post(self, page_path):
		articleId  = self.request.get("article-isLatest")
		isLatest   = self.request.get("article-isLatest")

		logging.info("ModnicaArticlesVersions:post(): ====> articleId=" + str(articleId))

		articles  = Article.all().filter("isLatest", True).filter("pagePath =", page_path).fetch(10)
		article = None
		if articles:
			for article in articles:
				if article.key().id() != articleId:
					article.isLatest = False
					logging.info("DEBUG: ====> clearing isLatest for " + str(article.key().id()))
					article.put()
				else:
					logging.info("no need to update isLatest for "+page_path+" : " + str(article.key().id()))
					self.redirect("/articles")
					return

		article    = Article.get_by_id(int(articleId))
		if article:
			article.isLatest = bool(isLatest)
			logging.info("DEBUG: ====> setting isLatest=" + str(isLatest) + " for " + str(articleId))
			article.put()
		memcache.flush_all()

		self.redirect("/articles")

class ModnicaArticlesPost(ModnicaAccount):
	def render_form(self, title="", content="", error="", **kw):
		self.render_front("post_article.html", title=title, content=content, error=error, **kw)

	def get(self):
		self.render_form()
		
	def post(self):
		title = self.request.get("title")
		content   = self.request.get("content")
		if title and content:
			a = Article(title=title,content=content,isLatest=True)
			a.put()
			memcache.flush_all()
			
			self.redirect("/articles")
		else:
			error = "we need both title and content!"
			self.render_form(title, content, error)

class ModnicaArticlesEdit(ModnicaAccount):
	def render_form(self, page_id, title="", content="", error="", **kw):
		self.render_front("edit_article.html", title=title, content=content, error=error, **kw)

	def get(self, page_path, page_id):
		username = self.getCurrentUsername()
		if not username:
			self.redirect("/login")
			return		
		
		title    = self.request.get("title")
		content  = self.request.get("content")
		pagePath = self.request.get("pagePath")
		created    = ""
		key      =  "page-"+page_id+"-"+pagePath
		logging.error("FIXME: " +title+"/"+content+" >> id=<"+page_id+">, pagePath=<"+pagePath+">, path=<"+page_path+">")
		if not title or not content:
			entry, cache_age_message = getFromCacheOrDb(key, pagePath, page_id)
			if entry:
				title = entry.title
				content  = entry.content
				pagePath = entry.pagePath
				created    = entry.created
				createdBy  = entry.createdBy
				logging.error("prepared for page edit:" + page_id + page_path)
			else:
				logging.error("ModnicaArticlesEdit:get(): entry not found: " + page_id + page_path)
				self.redirect("/articles/post")
				return
		self.render_form(page_id, title=title, content=content, pagePath=pagePath, cache_age_message=cache_age_message)
		
	def post(self, page_id, page_path):
		username = self.getCurrentUsername()
		error = None
		if not username:
			self.redirect("/login")
			return
		title = self.request.get("title")
		content  = self.request.get("content")
		pagePath = self.request.get("pagePath")
		if not title:
			error = "Title is mandatory"
		if not content:
			error = "The article is empty"
		if not pagePath:
			error = "The path is empty"
		if error:
			self.render_front("form.html", title=title, body=body, pagePath=pagePath)
			return
		query = Article.all()
		query.filter("pagePath =", pagePath)
		query.filter("isLatest =", True)
		logging.error("DB QUERY: " + show_query(query))
		entries = query.fetch(100)
		for e in entries:
			logging.error("===========+> CLEARING IS_LATEST for " + pagePath + ", id=" + str(e.key().id()))
			e.isLatest = False
			logging.error("e=<"+str(e)+">")
			saveRecord(page_path, e)
		a = Article(title=title, content=content, createdBy=username, pagePath=pagePath, isLatest=True)
		saveRecord(page_path, a)
		self.redirect("/articles/" + pagePath)
		memcache.flush_all()

class ModnicaArticlesView(ModnicaAccount):
	def render_form(self, page_id, title="", content="", error="", **kw):
		self.render_front("view_article.html", title=title, content=content, error=error, **kw)

	def get(self, page_path, page_id, pagePath):
		username = self.getCurrentUsername()
		logging.error("ModnicaArticlesView:get(): id=<"+page_id+">, pagePath=<"+pagePath+">, path=<"+page_path+">")
		
		key      =  "page-"+page_id+"-"+page_path
		entry, cache_age_message = getFromCacheOrDb(key, page_path, page_id)
		if entry:
			title = entry.title
			content  = entry.content
			created    = entry.created
			createdBy  = entry.createdBy
			logging.error("prepared for page view:" + page_id + page_path)
		else:
			logging.error("ModnicaArticlesView:get(): entry not found: " + page_id + page_path)
			self.redirect("/articles")
			return
		self.render_form(page_id, title=title, content=content, cache_age_message=cache_age_message)

#----------------------------------------------
# [+] UTILS
#----------------------------------------------


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE    = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
COOKIE_RE   = re.compile(r'.+=; Path=/')

def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)

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
# [+] CACHE
#----------------------------------------------

def getFromCacheOrDb(key, page_path, page_id = None, pagePath = None):
	data = memcache.get(key)
	cache_age=0
	entry = None

	if not page_id and not pagePath:
		logging.error("no data is provided!")
		return None, "not cached"
	
	if data is None:
		if page_id:
			logging.error("DB QUERY: get_by_id()")
			entry = Article.get_by_id(int(page_id))
		else:
			query = Article.all()
			query.filter("pagePath =", pagePath)
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
		query = Article.all()
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
		self.render("signup.html", username = username,
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
		self.redirect("/")
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
		self.render("login.html", username=username,
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
		self.redirect("/")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGOUT
#----------------------------------------------

class ModnicaLogout(MainPageHandler):
  def get(self):
	self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	self.redirect("/login")

#----------------------------------------------
# [+] MAP
#----------------------------------------------

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

def gmaps_img(points):
    return GMAPS_URL + '&'.join('markers=%s,%s' % (p.lat, p.lon) for p in points)

#----------------------------------------------
# [+] USER
#----------------------------------------------

class User(db.Model):
	username       = db.StringProperty(required = True)
	email          = db.TextProperty()
	password_hash  = db.TextProperty(required = True)
	created        = db.DateTimeProperty(auto_now_add = True)
	isAdmin        = db.BooleanProperty(default = False)

#----------------------------------------------
# [+] ARTICLE
#----------------------------------------------

class Article(db.Model):
	title     = db.StringProperty(required = True)
	content   = db.TextProperty(required = True)
	pagePath  = db.StringProperty()
	isMain    = db.BooleanProperty(default = False)
	isLatest  = db.BooleanProperty(default = False)
	idInMenu  = db.IntegerProperty(default = -1)
	created   = db.DateTimeProperty(auto_now_add = True)
	createdBy = db.StringProperty()

def top_articles(update = False):
	key = 'top'
	articles = memcache.get(key)
	if articles is None or update: 
		logging.error("DB QUERY :: SELECT * FROM Article")
		articles = db.GqlQuery("SELECT * FROM Article "
						   "ORDER BY created DESC "
						   "LIMIT 100")
		# prevent the runnning of multiple queries
		articles = list(articles)
		memcache.set(key, articles)
	else:
		logging.error("used CACHE with key=" + key)
	return articles

#----------------------------------------------
# [+] MAIN
#----------------------------------------------

class MainPage(ModnicaAccount):
	def render_form(self, title="", content="", error=""):
		query = Article.all()
		query.filter("isMain =", True)
		query.filter("isLatest =", True)
		entries, cache_age_message = self.getDbEntries("main-page", query, 1)
		
		if entries is None:
			logging.error("MAIN PAGE NOT FOUND")
		self.render_front("main.html", title=title, content=content, error=error, entries=entries, cache_age_message=cache_age_message)

	def get(self):
		self.render_form()

#----------------------------------------------
# [+] ROUTING
#----------------------------------------------

PAGE_RE = r'((?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication(
   [
	('/', 	            				MainPage),
	('/users',    						ModnicaUsers),
	('/articles', 						ModnicaArticles),
	('/articles/post', 					ModnicaArticlesPost),
	('(/articles/edit/?([0-9]*))', 		ModnicaArticlesEdit),
	('/articles/versions/' + PAGE_RE, 	ModnicaArticlesVersions),
	('(/articles/?([0-9]*))/' + PAGE_RE,ModnicaArticlesView),
	('/signup',   						ModnicaSignup),
	('/login',         					ModnicaLogin),
	('/logout',         				ModnicaLogout)
	],
   debug=True)


app.run()

