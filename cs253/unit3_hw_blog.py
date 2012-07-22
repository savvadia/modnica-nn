import os
import webapp2
import jinja2
import logging
import urllib

from google.appengine.ext import db

template_dir =  os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

def trace(text="", f="", l=""):
	logging.info("DEBUG: ====>" + text)

class Unit3_handler(webapp2.RequestHandler):
  def render_str(self, template, **params):
  	template = jinja_env.get_template(template)
  	return template.render(params)
  
  def render(self, template, **kw):
  	self.write(self.render_str(template, **kw))

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

class BlogEntry(db.Model):
	title     = db.StringProperty(required = True)
	body      = db.TextProperty(required = True)
	created   = db.DateTimeProperty(auto_now_add = True)

class BlogPage(Unit3_handler):
	def render_front(self):
		#logging.info("DEBUG: ====>" + "BlogPage.render_front()")
		entries = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC LIMIT 10")
		#for e in entries:
		#	debug = db.to_dict(e)
		#	logging.info("DEBUG: ====>" + str(debug) + " ::: ")
		self.render("unit3_blog.html", entries=entries)

	def get(self):
		logging.info("DEBUG: ====>" + "BlogPage.get()")
		self.render_front()


class BlogNewEntry(Unit3_handler):
	def render_front(self, title="", body="", error=""):
		self.render("unit3_blog_new_entry.html", title=title, body=body, error=error)
		
	def get(self):
		self.render_front()
		
	def post(self):
		title = self.request.get("subject")
		body  = self.request.get("content")
		if title and body:
			a = BlogEntry(title=title, body=body)
			a.put()
			#logging.info("DEBUG: ====>" + str(db.to_dict(a)) + " ::: " + str(a.key().id()))
			self.redirect("/unit3_hw_blog/" + str(a.key().id()))
		else:
			error = "we need both subject and content!"
			self.render_front(title, body, error)

class BlogOneEntry(Unit3_handler):
	def render_front(self, entry = "", error=""):
		self.render("unit3_blog_one_entry.html", entry=entry, error=error)
		
	def get(self, entryId):
		entryId = int(urllib.unquote(entryId))
		#logging.info("DEBUG: ====>" + str(entryId) +" <<")
		entry = BlogEntry.get_by_id(entryId)
		if entry:
			self.render_front(entry)
		else:
			self.render_front(error="Blog entry " + str(entryId) + " doesn't exist!")


app = webapp2.WSGIApplication(
                               [('/unit3_hw_blog', BlogPage),
                                ('/unit3_hw_blog/([0-9]+)', BlogOneEntry),
                                ('/unit3_hw_blog/newpost', BlogNewEntry)],
                               debug=True)

app.run()

