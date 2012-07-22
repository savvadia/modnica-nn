import os
import webapp2
import jinja2
import logging
import hashlib
import hmac

from google.appengine.ext import db

template_dir =  os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET="some cool secret is here!"

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    s = h.partition("|")[0]
    if h == make_secure_val(s):
        return s
    return None



class Unit4_handler(webapp2.RequestHandler):
  def render_str(self, template, **params):
  	template = jinja_env.get_template(template)
  	return template.render(params)
  
  def render(self, template, **kw):
  	self.write(self.render_str(template, **kw))

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

class CookiePage(Unit4_handler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
		visits_cookie_val = self.request.cookies.get('visits', '0')
		visits = check_secure_val(visits_cookie_val)
		if visits:
			logging.info("==> " + visits_cookie_val + " -> " + visits)
			visits = int(visits) + 1
		else:
			logging.info("==> " + visits_cookie_val + " -> None")
			visits = 1
		self.response.headers.add_header('Set-Cookie', 'visits=%s' % make_secure_val(str(visits)))
		self.write("You've been here %s times!\n" %visits)
		if visits > 10000:
			self.write("You're the best ever!")
		else:
			self.write("Keep coming...")
		

app = webapp2.WSGIApplication(
                               [('/unit4_cookie', CookiePage)],
                               debug=True)

app.run()


