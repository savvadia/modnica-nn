import os
import webapp2
import jinja2
import json
import urllib2

from xml.dom import minidom
from google.appengine.ext import db

template_dir =  os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class Unit3_handler(webapp2.RequestHandler):
  def render_str(self, template, **params):
  	template = jinja_env.get_template(template)
  	return template.render(params)
  
  def render(self, template, **kw):
  	self.write(self.render_str(template, **kw))

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

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


class Art(db.Model):
	title   = db.StringProperty(required = True)
	art     = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords  = db.GeoPtProperty()

class AsciiPage(Unit3_handler):
	def render_front(self, title="", art="", error=""):
		arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
		# prevent the runnning of multiple queries
		arts = list(arts)

		points = filter(None, (a.coords for a in arts))
		img_url = None
		if points:
			img_url = gmaps_img(points)
		
		self.render("unit3_form.html", title=title, art=art, error=error, arts=arts, img_url=img_url)

	def get(self):
		self.write(repr(get_coords(self.request.remote_addr)))
		self.render_front()
		
	def post(self):
		title = self.request.get("title")
		art   = self.request.get("art")
		if title and art:
			a = Art(title=title,art=art)
			coords = get_coords(self.request.remote_addr)
			if coords:
				a.coords = coords
			a.put()
			
			self.redirect("/unit5_ascii_w_map")
		else:
			error = "we need both title and artwork!"
			self.render_front(title, art, error)

app = webapp2.WSGIApplication(
                               [('/unit5_ascii_w_map', AsciiPage)],
                               debug=True)

app.run()

