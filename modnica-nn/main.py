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
import time 
import os
import urllib

from xml.dom import minidom
from google.appengine.api import users 
from google.appengine.api import images 
from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.ext.webapp.util import run_wsgi_app

from django.utils import simplejson  

template_dir =  os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

jinja_env.globals['get_serving_url'] = images.get_serving_url

# GAE creates default logger before the execution reaches this file, so we 
# set default logger to WARNINGS and add new loggers and set level for them
logging.getLogger().setLevel(logging.INFO)

h = logging.StreamHandler()
f = logging.Formatter("%(module)20s:%(lineno)-4s %(levelname)-7s %(name)-4s|%(funcName)16s - %(message)s")
h.setFormatter(f)

logging.getLogger().handlers[0].setFormatter(f)

trace_db   = logging.getLogger("db")
trace_art  = logging.getLogger("art")
trace_vit  = logging.getLogger("vit")
trace_gal  = logging.getLogger("gal")
trace_user = logging.getLogger("user")
trace_cach = logging.getLogger("cach")
trace_prod = logging.getLogger("prod")
trace_phot = logging.getLogger("phot")

trace_db.setLevel(   logging.INFO)
trace_art.setLevel(  logging.DEBUG)
trace_vit.setLevel(  logging.DEBUG)
trace_gal.setLevel(  logging.DEBUG)
trace_user.setLevel( logging.INFO)
trace_cach.setLevel( logging.INFO)
trace_prod.setLevel( logging.DEBUG)
trace_phot.setLevel( logging.DEBUG)

# no reason to add new handlers, because default formatting is ok
#if len(trace_db.handlers) == 0:
#	trace_db.addHandler(h)
#	trace_vit.addHandler(h)
#	trace_gal.addHandler(h)
#	trace_user.addHandler(h)

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
    trace_user.debug("==> check_secure_val: secure_val=%s" % (secure_val))
    val = secure_val.partition("|")[0]
    val = secure_val.partition("|")[0]
    trace_user.debug("==> check_secure_val: secure_val=%s, val=%s" % (secure_val,val))
    if secure_val == make_secure_val(val):
        return val
    return None

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(10))


def make_password_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    trace_user.debug("==> make_password_hash: n=" + name + " s=" + salt + " p=" + password)
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

class Account(MainPageHandler):
	def render_front(self, template, cache_age_message=dict(text="Page is not cached", key=None), activeMenuItem="undef", **kw):
		message = ""
		username_cookie      = self.request.cookies.get('user_id', None)
		user = None
		trace_user.debug("Account: cookie=" + str(username_cookie))
		trace_cach.debug("cache_age_message=" + str(cache_age_message))
		if username_cookie:
			username = check_secure_val(username_cookie)
			if username:
				trace_user.debug("Account username=" + username)
				query = User.all().filter("username =", username)
				user, ignored_cache_age_message = self.getDbEntry("username"+username, query)
		cookie_message="cookie=%s, empty=%s" % (username_cookie, 
		                                        str(valid_cookie(username_cookie)))

		self.render(template, user=user,
		                      cookie_message=cookie_message,
		                      cache_age_message=cache_age_message,
		                      activeMenuItem=activeMenuItem, **kw)

	def getCurrentUsername(self):
		username_cookie      = self.request.cookies.get('user_id', None)
		trace_user.debug("Account cookie=" + username_cookie)
		if username_cookie:
			username = check_secure_val(username_cookie)
			if username:
				return username
		return None
	
	# returns one entry and text message about cache age
	def getDbEntry(self, key, query):
		if not key:
			trace_db.exception("getDbEntry(): WARNING: no key is provided")
		else:
			data = memcache.get(key)
			if data:
				entry, saving_time = data[0], data[1]
				if key.startswith("username") == False: 
					trace_db.debug("used CACHE with key=" + key)
				else:
					trace_user.debug("used CACHE with key=" + key)
				diff = datetime.datetime.now() - saving_time
				cache_age_message = dict(text="Queried %s seconds ago by key=<%s>" % (diff.seconds, key), key=key)
				return entry, cache_age_message
		
		if not query:
			trace_db.exception("getDbEntry(): ERROR: no query is provided, key=" + key)
			return None, "not cached"
			
		trace_db.warn("====> DB QUERY: " + show_query(query))
		entries = query.fetch(1)
		if not entries:
			trace_db.warn("getDbEntry(): ERROR: query returned no data, key=" + key)
			return None, "not cached"
			
		entry = entries[0]
		memcache.set(key, (entry, datetime.datetime.now()))
		trace_db.warn("stored CACHE for " + key)
		return entry, dict(text="Queried NOW by key=<%s>" % key, key=key)
		
	# returns one entry by its ID and text message about cache age
	def getDbEntryById(self, objectName, objectId = -1):
		if not objectName:
			trace_db.exception("getDbEntryById(): ERROR: objectName is not provided")
			return None, "not cached"
		if not objectId or objectId == -1:
			trace_db.exception("getDbEntryById(): ERROR: objectId is not provided: " + str(objectId))
			return None, "not cached"
		
		key = objectName + str(objectId)
		data = memcache.get(key)
		if data:
			entry, saving_time = data[0], data[1]
			trace_db.info("used CACHE with key=" + key)
			diff = datetime.datetime.now() - saving_time
			cache_age_message = dict(text="Queried %s seconds ago by key=<%s>" % (diff.seconds, key), key=key)
			return entry, cache_age_message
		query = "SELECT * FROM " + objectName + " WHERE __key__ = KEY('" + objectName + "', " + str(objectId) + ")"
		trace_db.warn("====> DB QUERY: by ID:" + query)
		query = db.GqlQuery(query)
		entries = query.fetch(1)
		if not entries:
			trace_db.warn("getDbEntryById(): ERROR: query returned no data, key=" + key)
			return None, "not cached"
		trace_db.debug("stored ==> got " + str(entry) + "; " + repr(entry) + + "; key="+ key)
		entry = entries[0]
		memcache.set(key, (entry, datetime.datetime.now()))
		trace_db.warn("stored CACHE for " + key)
		return entry, dict(text="Queried NOW by key=<%s>" % key, key=key)
		
	# returns one entry and text message about cache age
	def getDbEntries(self, key, query, noOfEntries = 100):
		if not key:
			trace_db.exception("getDbEntries(): WARNING: no key is provided")
		else:
			data = memcache.get(key)
			if data:
				entries, saving_time = data[0], data[1]
				trace_db.info("used CACHE with key=" + key)
				diff = datetime.datetime.now() - saving_time
				cache_age_message = dict(text="Queried %s seconds ago by key=<%s>" % (diff.seconds, key), key=key)
				return entries, cache_age_message
		
		if not query:
			trace_db.exception("getDbEntries(): ERROR: no query is provided, key=" + key)
			return None, "not cached"
			
		trace_db.warn("###> DB QUERY: " + show_query(query))
		entries = query.fetch(noOfEntries)
		if not entries:
			trace_db.warn("getDbEntries(): ERROR: query returned no data, key=" + key)
			
		memcache.set(key, (entries, datetime.datetime.now()))
		trace_db.warn("stored CACHE for " + key)
		return entries, dict(text="Queried NOW by key=<%s>" % key, key=key)

	def saveObj(self, obj, keyList = {}):
		obj.put()
		trace_db.warn("#### DB QUERY: SAVED [" + obj.__class__.__name__ + "]ID=" + str(obj.key().id()))
		trace_db.debug("#### DB QUERY: SAVED " + obj.to_str())
		
		for key in keyList:
			memcache.delete(key)
		trace_db.warn("cleared CACHE for " + str(keyList))

	def clearCache(self, key):
		memcache.delete(key)
		trace_db.warn("cleared CACHE for " + key)
		
	def getMaxIdOnVitrina(self):
		query = Product.all()
		query.filter("idOnVitrina !=", -1)
		query.filter("isLatest =", True)
		query.order("idOnVitrina")
		entries, cache_age_message = self.getDbEntries("vitrina", query)
		if not entries:
				return -1
		idOnVitrina = -1
		for e in entries:
			if e.idOnVitrina > idOnVitrina:
				idOnVitrina = e.idOnVitrina
		trace_vit.info("getMaxIdOnVitrina returns idOnVitrina=" + str(idOnVitrina))
		return idOnVitrina

	def getPrevEntryOnVitrina(self, idOnVitrina):
		if idOnVitrina == -1:
			logging.error("getPrevEntryOnVitrina(): idOnVitrina = -1")
			return None
			
		query = Product.all()
		query.filter("idOnVitrina !=", -1)
		query.filter("isLatest =", True)
		query.order("idOnVitrina")
		entries, cache_age_message = self.getDbEntries("vitrina", query)
		if not entries:
			trace_vit.warn("getPrevEntryOnVitrina(): no entries on vitrina")
			return None
		foundEntry = None
		for e in entries:
			trace_vit.error("getPrevEntryOnVitrina(): FIXME CHECKING ID=" + str(e.key().id())+ "." + str(e.idOnVitrina) + " < " + str(idOnVitrina))
			if foundEntry is None:
				if e.idOnVitrina == idOnVitrina:
					continue
				elif e.idOnVitrina < idOnVitrina:
					foundEntry = e
					trace_vit.debug("getPrevEntryOnVitrina(): FIXME FOUND ID=" + str(foundEntry.key().id())+ " as prev entry for idOnVitrina=" + str(idOnVitrina))
			# min ... found < desired < given ... max
			elif foundEntry.idOnVitrina < e.idOnVitrina and e.idOnVitrina < idOnVitrina:
				foundEntry = e
				trace_vit.debug("getPrevEntryOnVitrina(): FIXME FOUND ID=" + str(foundEntry.key().id())+ " as prev entry for idOnVitrina=" + str(idOnVitrina))
			else:
				trace_vit.debug("getPrevEntryOnVitrina(): FIXME IGNORES ID=" + str(foundEntry.key().id())+ "." + str(foundEntry.idOnVitrina) + " < " + str(e.key().id())+ "." + str(e.idOnVitrina) + " < " + str(idOnVitrina))
		if not foundEntry:
			trace_vit.warn("getPrevEntryOnVitrina(): prev entry not found for idOnVitrina=" + str(idOnVitrina))
			return None
		trace_vit.warn("getPrevEntryOnVitrina(): FIXME FOUND FINAL ID=" + str(foundEntry.key().id())+ " as prev entry for idOnVitrina=" + str(idOnVitrina))
		return foundEntry

	def getNextEntryOnVitrina(self, idOnVitrina):
		if idOnVitrina == -1:
			trace_vit.error("getNextEntryOnVitrina(): idOnVitrina = -1")
			return None
			
		query = Product.all()
		query.filter("idOnVitrina !=", -1)
		query.filter("isLatest =", True)
		query.order("idOnVitrina")
		entries, cache_age_message = self.getDbEntries("vitrina", query)
		if not entries:
			trace_vit.error("getNextEntryOnVitrina(): no entries on vitrina")
			return None
		foundEntry = None
		for e in entries:
			trace_vit.debug("getNextEntryOnVitrina(): FIXME CHECKING ID=" + str(idOnVitrina) + " < " + str(e.key().id())+ "." + str(e.idOnVitrina))
			if foundEntry is None:
				if e.idOnVitrina == idOnVitrina:
					continue
				elif idOnVitrina < e.idOnVitrina:
					foundEntry = e
					trace_vit.debug("getNextEntryOnVitrina(): FIXME FOUND ID=" + str(foundEntry.key().id())+ " as next entry for idOnVitrina=" + str(idOnVitrina))
			# min ... given < desired < found ... max
			elif idOnVitrina < e.idOnVitrina and e.idOnVitrina < foundEntry.idOnVitrina:
				foundEntry = e
				trace_vit.debug("getNextEntryOnVitrina(): FIXME FOUND ID=" + str(foundEntry.key().id())+ " as next entry for idOnVitrina=" + str(idOnVitrina))
			else:
				trace_vit.debug("getNextEntryOnVitrina(): FIXME IGNORES ID=" + str(idOnVitrina) + " < " + str(e.key().id())+ "." + str(e.idOnVitrina) + " < " + str(foundEntry.key().id())+ "." + str(foundEntry.idOnVitrina))
		if not foundEntry:
			trace_vit.warn("getNextEntryOnVitrina(): next entry not found for idOnVitrina=" + str(idOnVitrina))
			return None
		
		trace_vit.warn("getNextEntryOnVitrina(): FIXME FOUND FINAL ID=" + str(foundEntry.key().id())+ " as next entry for idOnVitrina=" + str(idOnVitrina))
		return foundEntry

class AccountClearCache(Account):
	def get(self, key):
		self.clearCache(key)
		self.redirect("/")

class AccountMain(Account):
	def render_front(self, template, **kw):
		super(AccountMain, self).render_front(template=template, activeMenuItem="main", **kw)

class AccountCabinet(Account):
	def render_front(self, template, **kw):
		super(AccountCabinet, self).render_front(template=template, activeMenuItem="cabinet", **kw)

class AccountVitrina(Account):
	def render_front(self, template, **kw):
		super(AccountVitrina, self).render_front(template=template, activeMenuItem="vitrina", **kw)

class AccountGallery(Account):
	def render_front(self, template, **kw):
		super(AccountGallery, self).render_front(template=template, activeMenuItem="gallery", **kw)

#----------------------------------------------
# [+] USERS
#----------------------------------------------

class ModnicaUsers(AccountCabinet):

	def get(self):
		key = "users-list"
		query = User.all()
		query.order("-created")
		entries, cache_age_message = self.getDbEntries(key, query)
		self.render_front("users.html", entries=entries, cache_age_message=cache_age_message)

	def post(self):
		logging.info("ModnicaUsers:post(): ====>" + str(self.request) + " ::: ")
		
		userId  = self.request.get("user-id")
		isAdmin = self.request.get("user-isAdmin")
		user = User.get_by_id(int(userId))
		if user:
			user.isAdmin = bool(isAdmin)
			logging.info("DEBUG: ====> isAdmin=" + isAdmin)
			user.put()

		self.redirect("/users")

#----------------------------------------------
# [+] ARTICLES
#----------------------------------------------

class ModnicaArticles(AccountCabinet):

	def get(self):
		key = "articles-list"
		query = Article.all()
		query.filter("isLatest =", True)
		query.order("title")
		entries, cache_age_message = self.getDbEntries(key, query)
		self.render_front("articles.html", entries=entries, cache_age_message=cache_age_message)

	def post(self):
		trace_art.debug("ModnicaUsers:post(): ====>" + str(self.request.params) + " ::: ")
		
		articleId  = self.request.get("article-isMain")

		key = "article-isMain"
		query = Article.all().filter("isMain", True)

		# clear isMain flag. There should be just one record, but just in case we'll fetch several
		articles, cache_age_message  = self.getDbEntries(key, query) 
		if articles:
			for article in articles:
				if article.key().id() != articleId:
					article.isMain = False
					trace_art.debug("DEBUG: ====> clearing isMain for " + str(article.key().id()))
					self.saveObj(article, {"article-" + str(article.key().id())})
				else:
					self.redirect("/articles")
		
		article    = Article.get_by_id(int(articleId))
		if article:
			article.isMain = True
			trace_art.info("setting isMain=" + str(True) + " for <" + article.pagePath + "> articleId=" + str(articleId))
			self.saveObj(article, {"articles-list", "main-page"})

		self.redirect("/articles")

class ModnicaArticlesVersions(AccountCabinet):

	def get(self, pagePath):
		key = "pagePath-" + pagePath
		trace_art.info("ModnicaArticlesVersions: pagePath=" + pagePath + ", key=" + key)
		query = Article.all()
		query.filter("pagePath =", pagePath)
		query.order("-created")
		entries, cache_age_message = self.getDbEntries(key, query)
		self.render_front("articles_versions.html", entries=entries, cache_age_message=cache_age_message)

	def post(self, page_path):
		articleId  = self.request.get("article-isLatest")
		isLatest   = self.request.get("article-isLatest")

		trace_art.info("ModnicaArticlesVersions: articleId=" + str(articleId))

		key = "article-isLatest-" + page_path
		query = Article.all().filter("isLatest", True).filter("pagePath =", page_path)

		# clear isLatest flag. There should be just one record, but just in case we'll fetch several
		articles, cache_age_message  = self.getDbEntries(key, query) 
		article = None
		if articles:
			for article in articles:
				if article.key().id() != articleId:
					article.isLatest = False
					trace_art.info("DEBUG: clearing isLatest for " + str(article.key().id()))
					article.put()
				else:
					trace_art.info("no need to update isLatest for "+page_path+" : " + str(article.key().id()))
					self.redirect("/articles")
					return

		article    = Article.get_by_id(int(articleId))
		if article:
			article.isLatest = bool(isLatest)
			trace_art.info("setting isLatest=" + str(isLatest) + " for " + str(articleId))
			article.put()
		memcache.flush_all()

		self.redirect("/articles")

class ModnicaArticlesPost(AccountCabinet):
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

class ModnicaArticlesEdit(AccountCabinet):
	def render_form(self, page_id, title="", content="", error="", **kw):
		self.render_front("edit_article.html", title=title, content=content, error=error, **kw)

	def get(self, page_path, page_id):
		username = self.getCurrentUsername()
		if not username:
			self.redirect("/login")
			return		
		
		key      =  "article-"+page_id
		query = Article.all().filter("__key__ =", db.Key.from_path('Article', int(page_id)))
		entry, cache_age_message = self.getDbEntry(key, query)
		if not entry:
			trace_art.error("ModnicaArticlesEdit:get(): entry not found: " + page_id + page_path)
			self.redirect("/articles/post")
			return
		self.render_form(page_id, title=entry.title, content=entry.content, pagePath=entry.pagePath, createdBy=entry.createdBy, cache_age_message=cache_age_message)
		
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
		entries, ignored_cache_age_message = self.getDbEntries("allLatest", query, 100)
		for e in entries:
			trace_art.warn("CLEARING IS_LATEST for " + pagePath + ", id=" + str(e.key().id()))
			e.isLatest = False
			self.saveObj(e, {e.pagePath})
		a = Article(title=title, content=content, createdBy=username, pagePath=pagePath, isLatest=True)
		self.saveObj(a, {pagePath})
		self.redirect("/articles/" + pagePath)
		memcache.flush_all()

class ModnicaArticlesView(Account):
	def render_form(self, page_id, title="", content="", error="", **kw):
		self.render_front("view_article.html", title=title, content=content, error=error, **kw)

	def get(self, page_id, pagePath):
		username = self.getCurrentUsername()
		trace_art.debug("ModnicaArticlesView: id=<"+page_id+">, pagePath=<"+pagePath+">")
		
		if page_id:
			key      =  "article-"+str(page_id)
			query = Article.all().filter("__key__ =", db.Key.from_path('Article', int(page_id)))
		else:
			key      =  "article-"+str(pagePath)
			query = Article.all().filter("pagePath =", pagePath).filter("isLatest =", True)
		entry, cache_age_message = self.getDbEntry(key, query)
		if not entry:
			trace_art.error("404 - entry not found: page_id=" + page_id + ", pagePath=" + pagePath)
			self.error(404)
			return
		self.render_form(page_id, title=entry.title, content=entry.content, cache_age_message=cache_age_message)

#----------------------------------------------
# [+] VITRINA
#----------------------------------------------

class ModnicaVitrina(AccountVitrina):

	def get(self):
		key = "vitrina"
		query = Product.all()
		query.filter("isLatest =", True)
		query.filter("idOnVitrina !=", -1)
		query.order("idOnVitrina")
		entries, cache_age_message = self.getDbEntries(key, query)
		if entries:
			self.render_front("vitrina.html", entries=entries, cache_age_message=cache_age_message)
		else:
			self.redirect("/")

class ModnicaVitrinaEdit(AccountCabinet):

	def get(self):
		key = "vitrina"
		query = Product.all()
		query.filter("isLatest =", True)
		query.filter("idOnVitrina !=", -1)
		query.order("idOnVitrina")
		entries, cache_age_message = self.getDbEntries(key, query)

		key = "vitrina-other"
		query = Product.all()
		query.filter("isLatest =", True)
		query.filter("idOnVitrina ==", -1)
		query.order("-created")
		entriesNotOnVitrina, cache_age_message = self.getDbEntries(key, query)
		
		if entries or entriesNotOnVitrina:
			self.render_front("edit_vitrina.html", entries=entries, entriesNotOnVitrina=entriesNotOnVitrina, cache_age_message=cache_age_message)
		else:
			self.render_front("empty_vitrina.html", cache_age_message=cache_age_message)

	def post(self):
		productId  = int(self.request.get("product-id"))
		moveIn     = self.request.get("moveIn")
		moveOut    = self.request.get("moveOut")
		moveLeft   = self.request.get("moveLeft")
		moveRight  = self.request.get("moveRight")

		if moveIn:
			idOnVitrina = 1+ self.getMaxIdOnVitrina()
			trace_vit.info("ModnicaVitrinaEdit:moveIn: ====> maxIdOnVitrina=" + str(idOnVitrina))
			entry, cache_age_message = self.getDbEntryById("Product", productId)
			if not entry:
				trace_vit.error("ModnicaVitrinaEdit:moveIn: ====> product not found id=" + str(productId))
				self.redirect("/vitrina/edit")
				return
			entry.idOnVitrina=idOnVitrina
			self.saveObj(entry, {"product-"+str(productId), "Product"+str(productId), "vitrina", "vitrina-other"})
			self.redirect("/vitrina/edit")
			return
		
		if moveOut:
			entry, cache_age_message = self.getDbEntryById("Product", productId)
			if not entry:
				trace_vit.error("ModnicaVitrinaEdit:====> product not found for id=" + str(productId))
				self.redirect("/vitrina/edit")
				return
			entry.idOnVitrina=-1
			self.saveObj(entry, {"product-"+str(productId), "Product"+str(productId), "vitrina", "vitrina-other"})
			self.redirect("/vitrina/edit")
			return
			
		if moveLeft or moveRight:
			entry, cache_age_message = self.getDbEntryById("Product", productId)
			if not entry:
				trace_vit.error("ModnicaVitrinaEdit ====> product not found for id=" + str(productId))
				self.redirect("/vitrina/edit")
				return
			if moveLeft:
				foundEntry = self.getPrevEntryOnVitrina(entry.idOnVitrina)
			else:
				foundEntry = self.getNextEntryOnVitrina(entry.idOnVitrina)
			if not foundEntry:
				if moveLeft:
					trace_vit.error("ModnicaVitrinaEdit ====> prev entry not found for idOnVitrina=" + str(entry.idOnVitrina))
				else:
					trace_vit.error("ModnicaVitrinaEdit ====> next entry not found for idOnVitrina=" + str(entry.idOnVitrina))
				self.redirect("/vitrina/edit")
				return
			if entry.key().id() == foundEntry.key().id():
				trace_vit.warn("ModnicaVitrinaEdit:post(): ====> got the same object id="+ str(foundEntry.key().id()) + " for idOnVitrina=" + str(entry.idOnVitrina))
			else:
				adjIdOnVitrina = foundEntry.idOnVitrina
				# swap
				foundEntry.idOnVitrina = entry.idOnVitrina
				entry.idOnVitrina = adjIdOnVitrina
				self.saveObj(entry,      {"product-" + str(productId), "Product" + str(productId), "vitrina"})
				self.saveObj(foundEntry, {"product-" + str(foundEntry.key().id()), "Product" + str(foundEntry.key().id()), "vitrina"})
			self.redirect("/vitrina/edit")
			return

#----------------------------------------------
# [+] PRODUCTS
#----------------------------------------------

class ModnicaProducts(Account):

	def get(self):
		key = "products-list"
		query = Product.all()
		query.filter("isLatest =", True)
		query.order("title")
		entries, cache_age_message = self.getDbEntries(key, query)
		if entries:
			self.render_front("products.html", entries=entries, cache_age_message=cache_age_message)
		else:
			self.redirect("/products/post")
			

class ModnicaProductsVersions(AccountCabinet):

	def get(self, pagePath):
		key = "pagePath-" + pagePath
		trace_prod.debug("ModnicaProductsVersions: pagePath=" + pagePath + ", key=" + key)
		query = Product.all()
		query.filter("pagePath =", pagePath)
		query.order("-created")
		entries, cache_age_message = self.getDbEntries(key, query)
		self.render_front("products_versions.html", entries=entries, cache_age_message=cache_age_message)

	def post(self, page_path):
		productId  = self.request.get("product-isLatest")
		isLatest   = self.request.get("product-isLatest")

		race_prod.debug("ModnicaProductsVersions:productId=" + str(productId))

		key = "product-isLatest-" + page_path
		query = Product.all().filter("isLatest", True).filter("pagePath =", page_path)

		# clear isLatest flag. There should be just one record, but just in case we'll fetch several
		products, cache_age_message  = self.getDbEntries(key, query) 
		product = None
		if products:
			for product in products:
				if product.key().id() != productId:
					product.isLatest = False
					trace_prod.info("DEBUG: ====> clearing isLatest for " + str(product.key().id()))
					product.put()
				else:
					trace_prod.info("no need to update isLatest for "+page_path+" : " + str(product.key().id()))
					self.redirect("/products")
					return

		product    = Product.get_by_id(int(productId))
		if product:
			product.isLatest = bool(isLatest)
			trace_prod.info("DEBUG: ====> setting isLatest=" + str(isLatest) + " for " + str(productId))
			product.put()
		memcache.flush_all()

		self.redirect("/products")

class ModnicaProductsPost(AccountCabinet):
	def render_form(self, title="", content="", error="", **kw):
		self.render_front("post_product.html", title=title, content=content, error=error, **kw)

	def get(self):
		self.render_form()
		
	def post(self):
		title     = self.request.get("title")
		content   = self.request.get("content")
		price     = self.request.get("price")
		pagePath  = self.request.get("pagePath")
		error = None

		if not title:
			error = "Title is mandatory"
		if not content:
			error = "The product is empty"
		if not pagePath:
			error = "The path is empty"
		if not price:
			error = "The price is empty"
		else:
			try:
				price = int(price)
			except TypeError:
				error = "The price should be a number"
		if error:
			self.render_form(title=title, content=content, pagePath=pagePath, error=error)
			return
		# clear latest flag
		query = Product.all()
		query.filter("pagePath =", pagePath)
		query.filter("isLatest =", True)
		entries, cache_age_message = self.getDbEntries("product-"+pagePath, query)
		for e in entries:
			trace_prod.info("===========+> CLEARING IS_LATEST for " + pagePath + ", id=" + str(e.key().id()))
			e.isLatest = False
			trace_prod.debug("e=<"+str(e)+">")
			self.saveObj(e, {"product-"+str(e.key().id()), "products-list"})
		a = Product(title=title,content=content, price=price, pagePath=pagePath, isLatest=True)
		self.saveObj(a, {"product-"+pagePath, "products-list", "vitrina-other"})
		self.redirect("/products")

class ModnicaProductsEdit(AccountCabinet):
	def render_form(self, page_id, title="", content="", error="", **kw):
		self.render_front("edit_product.html", title=title, content=content, error=error, **kw)

	def get(self, page_path, page_id):
		username = self.getCurrentUsername()
		if not username:
			self.redirect("/login")
			return		
		
		key      =  "product-"+page_id
		query = Product.all().filter("__key__ =", db.Key.from_path('Product', int(page_id)))
		entry, cache_age_message = self.getDbEntry(key, query)
		if not entry:
			trace_prod.error("ModnicaProductsEdit: entry not found: " + page_id + page_path)
			self.redirect("/products/post")
			return
		self.render_form(page_id, title=entry.title, content=entry.content, price=entry.price, pagePath=entry.pagePath, createdBy=entry.createdBy, idOnVitrina=entry.idOnVitrina, cache_age_message=cache_age_message)
		
	def post(self, page_id, page_path):
		username = self.getCurrentUsername()
		error = None
		if not username:
			self.redirect("/login")
			return
		title = self.request.get("title")
		content  = self.request.get("content")
		price  = int(self.request.get("price"))
		pagePath = self.request.get("pagePath")
		idOnVitrina = int(self.request.get("idOnVitrina"))
		isShownOnVitrina = self.request.get("isShownOnVitrina")
		trace_prod.debug("idOnVitrina=" + str(idOnVitrina) +" isShownOnVitrina= " + str(isShownOnVitrina))
		if not title:
			error = "Title is mandatory"
		if not content:
			error = "The product is empty"
		if not pagePath:
			error = "The path is empty"
		if error:
			self.render_front("form.html", title=title, body=body, pagePath=pagePath)
			return
		self.clearCache("vitrina")
		isNewOnVitrina = False
		if not isShownOnVitrina:
			idOnVitrina = -1
		else:
			if idOnVitrina == -1:
				isNewOnVitrina = True
				trace_vit.info("isNewOnVitrina= True")
		# clear latest flag
		query = Product.all()
		query.filter("pagePath =", pagePath)
		query.filter("isLatest =", True)
		entries, cache_age_message = self.getDbEntries("product-"+pagePath, query)
		for e in entries:
			trace_prod.info("===========+> CLEARING IS_LATEST for " + pagePath + ", id=" + str(e.key().id()))
			e.isLatest = False
			trace_prod.debug("e=<"+str(e)+">")
			self.saveObj(e, {"product-"+str(e.key().id()), "products-list"})
		# get max idOnVitrina
		if isNewOnVitrina == True:
			idOnVitrina = 1 + self.getMaxIdOnVitrina()
		a = Product(title=title, content=content, createdBy=username, pagePath=pagePath, price=price, idOnVitrina=idOnVitrina, isLatest=True)
		if isNewOnVitrina == True:
			self.saveObj(a, {"product-"+pagePath, "products-list", "vitrina"})
		else:
			self.saveObj(a, {"product-"+pagePath, "products-list"})
		self.clearCache("product-"+str(a.key().id()))
		self.redirect("/products/" + str(a.key().id()))


class ModnicaProductsView(Account):
	def render_form(self, page_id, title="", content="", error="", **kw):
		self.render_front("view_product.html", title=title, content=content, error=error, **kw)

	def get(self, page_path, page_id, pagePath):
		username = self.getCurrentUsername()
		trace_prod.debug("ModnicaProductsView:get(): id=<"+page_id+">, pagePath=<"+pagePath+">, path=<"+page_path+">")
		
		key      =  "product-"+page_id
		query = Product.all().filter("__key__ =", db.Key.from_path('Product', int(page_id)))
		entry, cache_age_message = self.getDbEntry(key, query)
		if not entry:
			trace_prod.error("ModnicaProductsView:get(): entry not found: " + page_id + page_path)
			self.redirect("/products")
			return
		self.render_form(page_id, title=entry.title, content=entry.content, cache_age_message=cache_age_message)

class ModnicaProductsViewByPath(Account):
	def render_form(self, title="", content="", error="", **kw):
		self.render_front("view_product.html", title=title, content=content, error=error, **kw)

	def get(self, page_path, pagePath):
		username = self.getCurrentUsername()
		trace_prod.debug("ModnicaProductsView: pagePath=<"+pagePath+">, path=<"+page_path+">")
		
		key      =  "product-"+pagePath
		query = Product.all().filter("pagePath", pagePath). filter("isLatest =", True)
		entry, cache_age_message = self.getDbEntry(key, query)
		if not entry:
			trace_prod.error("ModnicaProductsView: entry not found: " + page_path + "; " + page_path)
			self.redirect("/products")
			return
		self.render_form(title=entry.title, content=entry.content, cache_age_message=cache_age_message)


#----------------------------------------------
# [+] PHOTOS
#----------------------------------------------

class ModnicaPhotosPost(AccountCabinet, blobstore_handlers.BlobstoreUploadHandler):
	def render_form(self, upload_url="", title="", content="", error="", **kw):
		self.render_front("post_photo.html", upload_url=upload_url, title=title, content=content, error=error, **kw)

	def get(self):
		logging.info("ModnicaPhotosPost:get()")
		upload_url = blobstore.create_upload_url('/photos/post')
		self.render_form(upload_url=upload_url)
		
	def post(self):
		title     = self.request.get("title")
		content   = self.request.get("content")
		error = None

		logging.info("ModnicaPhotosPost:post()")
		#try:
		blob_info = self.get_uploads()[0]
		username=self.getCurrentUsername()
		if not title:
			error = "Title is mandatory"
		if error:
			blob_info.delete()
			self.render_form(title=title, content=content, error=error)
			return

		photo = Photo(title="123", content="", createdBy=username, blob_key=blob_info.key())
		self.saveObj(photo, {"gallery"})
		self.redirect('/photos/%d' % photo.key().id())
		#except:
		logging.info("ModnicaPhotosPost:post() EXCEPTION")
		#	error="Uploading failed"
		#	self.render_form(title=title, content=content, error=error)

class ModnicaPhotosView(AccountCabinet, blobstore_handlers.BlobstoreDownloadHandler):
	def render_form(self, photo, error="", **kw):
		self.render_front("view_photo.html", photo=photo, error=error, **kw)

	def get(self, photo_id):
		logging.info("ModnicaPhotosView:get()")
		photo = Photo.get_by_id(long(photo_id))
		if not photo:
		  self.error(404)
		  return
		self.render_form(photo=photo)
		# self.send_blob(photo_key)

class ModnicaPhotosDownload(AccountCabinet, blobstore_handlers.BlobstoreDownloadHandler):
	def get(self, photo_id):
		logging.info("ModnicaPhotosDownload:get()")
		photo = Photo.get_by_id(long(photo_id))
		if not photo:
		  self.error(404)
		  return
		self.send_blob(photo.blob_key, save_as=True)

class ModnicaGallery(AccountGallery):
	def get(self):
		logging.info("ModnicaGallery:get()")
		query = Photo.all()
		entries, cache_age_message = self.getDbEntries("gallery", query)
		self.render_front("gallery.html", entries=entries, cache_age_message=cache_age_message)

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

    res = ["*** %s.all()" % kind]
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
# [+] SIGNUP
#----------------------------------------------
class ModnicaSignup(Account):

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
		query = User.all()
		query.filter("isAdmin =", True)
		entries, cache_age_message = self.getDbEntries("admins", query)
		
		if len(entries) > 0:
			isAdmin = False
		else:
			isAdmin = True

		a = User(username=username, email=email, password_hash=password_hash, isAdmin=isAdmin)
		a.put()
		self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(username))
		logging.info("==> ModnicaSignup:post() OK: set cookie to " + make_secure_val(username))
		self.redirect("/")
		# ?username="+cgi.escape(username))

#----------------------------------------------
# [+] LOGIN
#----------------------------------------------

class ModnicaLogin(Account):

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

class ModnicaLogout(Account):
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
# [+] BASE MODEL
#----------------------------------------------

class GqlEncoder(simplejson.JSONEncoder): 

    """Extends JSONEncoder to add support for GQL results and properties. 

    Adds support to simplejson JSONEncoders for GQL results and properties by 
    overriding JSONEncoder's default method. 
    """ 

    # TODO Improve coverage for all of App Engine's Property types. 

    def default(self, obj):
        """Tests the input object, obj, to encode as JSON.""" 
        if hasattr(obj, '__json__'): 
            return getattr(obj, '__json__')() 
        if isinstance(obj, db.GqlQuery): 
            return list(obj) 
        elif isinstance(obj, db.Model): 
            properties = obj.properties().items() 
            output = {} 
            for field, value in properties: 
                output[field] = getattr(obj, field)
            return output 
        elif isinstance(obj, datetime.datetime): 
            output = {} 
            fields = ['day', 'hour', 'microsecond', 'minute', 'month', 'second', 'year'] 
            fields = [] 
            methods = ['ctime', 'isocalendar', 'isoformat', 'isoweekday', 'timetuple'] 
            methods = ['ctime'] 
            for field in fields: 
                output[field] = getattr(obj, field) 
            for method in methods: 
                output[method] = getattr(obj, method)() 
            output['epoch'] = time.mktime(obj.timetuple()) 
            return output
        elif isinstance(obj, datetime.date): 
            output = {} 
            fields = ['year', 'month', 'day'] 
            fields = [] 
            methods = ['ctime', 'isocalendar', 'isoformat', 'isoweekday', 'timetuple'] 
            methods = ['ctime'] 
            for field in fields: 
                output[field] = getattr(obj, field) 
            for method in methods: 
                output[method] = getattr(obj, method)() 
            output['epoch'] = time.mktime(obj.timetuple()) 
            return output 
        elif isinstance(obj, time.struct_time): 
            return list(obj) 
        elif isinstance(obj, users.User): 
            output = {} 
            methods = ['nickname', 'email', 'auth_domain'] 
            for method in methods: 
                output[method] = getattr(obj, method)() 
            return output 
        elif isinstance(obj, blobstore.BlobInfo): 
            output = {} 
            #methods = ['filename', 'size', 'content_type'] 
            #for method in methods: 
            #    output[method] = getattr(obj, method)() 
            return output 
        return simplejson.JSONEncoder.default(self, obj) 
        
class BaseModel(db.Model):
	def to_str(self):
		return GqlEncoder().encode(self)
 
#----------------------------------------------
# [+] USER
#----------------------------------------------

class User(BaseModel):
	username       = db.StringProperty(required = True)
	email          = db.TextProperty()
	password_hash  = db.TextProperty(required = True)
	created        = db.DateTimeProperty(auto_now_add = True)
	isAdmin        = db.BooleanProperty(default = False)
        
#----------------------------------------------
# [+] ARTICLE
#----------------------------------------------

class Article(BaseModel):
	title     = db.StringProperty(required = True)
	content   = db.TextProperty(required = True)
	pagePath  = db.StringProperty()
	isMain    = db.BooleanProperty(default = False)
	isLatest  = db.BooleanProperty(default = True)
	idInMenu  = db.IntegerProperty(default = -1)
	created   = db.DateTimeProperty(auto_now_add = True)
	createdBy = db.StringProperty()

#----------------------------------------------
# [+] PRODUCT
#----------------------------------------------

class Product(BaseModel):
	title        = db.StringProperty(required = True)
	content      = db.TextProperty(required = True)
	price        = db.IntegerProperty(default = 0)
	pagePath     = db.StringProperty(required = True)
	isLatest     = db.BooleanProperty(default = True)
	idOnVitrina  = db.IntegerProperty(default = -1)
	created      = db.DateTimeProperty(auto_now_add = True)
	createdBy    = db.StringProperty()

#----------------------------------------------
# [+] PHOTO
#----------------------------------------------

class Photo(BaseModel):
	title        = db.StringProperty(required = True)
	content      = db.StringProperty()
	blob_key     = blobstore.BlobReferenceProperty()
	created      = db.DateTimeProperty(auto_now_add = True)
	createdBy    = db.StringProperty()

#----------------------------------------------
# [+] MAIN
#----------------------------------------------

class MainPage(AccountMain):
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

def main():
	# Set the logging level in the main function
	# See the section on Requests and App Caching for information on how
	# App Engine reuses your request handlers when you specify a main function

	#logging.info("======================== START ============================")

	PAGE_RE = r'((?:[a-zA-Z0-9_-]+/?)*)'
	app = webapp2.WSGIApplication(
	   [
		('/', 	            				MainPage),
		('/users',    						ModnicaUsers),
		('/vitrina',    					ModnicaVitrina),
		('/vitrina/edit', 					ModnicaVitrinaEdit),

		('/articles', 						ModnicaArticles),
		('/articles/post', 					ModnicaArticlesPost),
		('(/articles/edit/?([0-9]*))', 		ModnicaArticlesEdit),
		('/articles/versions/' + PAGE_RE, 	ModnicaArticlesVersions),
		('/articles/([0-9]+)()',          ModnicaArticlesView),
		('/articles/?([0-9]*)/' + PAGE_RE,ModnicaArticlesView),

		('/products', 						ModnicaProducts),
		('/products/post', 					ModnicaProductsPost),
		('(/products/edit/?([0-9]*))', 		ModnicaProductsEdit),
		('/products/versions/' + PAGE_RE, 	ModnicaProductsVersions),
		('(/products/([0-9]+))()',          ModnicaProductsView),
		('(/products/' + PAGE_RE + ")",     ModnicaProductsViewByPath),

		('/gallery', 						ModnicaGallery),
		('/photos/post', 					ModnicaPhotosPost),
		('/photos/([0-9]+)', 		    	ModnicaPhotosView),
		('/photos/download/([0-9]+)',		ModnicaPhotosDownload),

		('/signup',   						ModnicaSignup),
		('/login',         					ModnicaLogin),
		('/logout',         				ModnicaLogout),

		('/clear_cache/' + PAGE_RE,    		AccountClearCache)
		],
	   debug=True)

	app.run()

if __name__ == '__main__':
    main()
