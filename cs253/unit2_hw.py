import webapp2
import cgi

description_rot13 = """
<b>HW2: ROT13</b><br><br> 
Enter the text in the textbox.
After submitting each letter will be shifted by 13 in the alphabet.<br>
Case is preserved.<br>
If submitted twice, the text is not changed.<br><br>
"""

form_hw2_rot13 = """

<form method="post">
It is HW2.<br>
Enter text and it will be encoded with ROT13.<br>
Submit twice and see the result.<br>
<textarea name="text" rows="10" cols="50">%(ROT13)s</textarea>
<input type="submit">
</form>

"""

class Hw2rot13(webapp2.RequestHandler):

  def convertRot13(self, text):
	data ="abcdefghijklmnopqrstuvwxyz"
	rot13="nopqrstuvwxyzabcdefghijklm"
	dataUp = data.upper()
	rot13Up = rot13.upper()
	result = []
	for i in range(len(text)):
		s_l = data.find(text[i])
		s_u = dataUp.find(text[i])
		if s_l != -1:
			#self.response.out.write(text[i] + "==> L: " + str(s_l) + " / " + str(s_u) + " => " + rot13[s_l] + "<br>")
			result.append(rot13[s_l])
		elif s_u != -1:
			#self.response.out.write(text[i] + "==> L: " + str(s_l) + " / " + str(s_u) + " => " + rot13Up[s_u] + "<br>")
			result.append(rot13Up[s_u])
		else:
			result.append(text[i])
	#self.response.out.write( str(result)  + "<br>")
	return  cgi.escape("".join(result))

  def write_form(self, text=""):
	self.response.out.write(description_rot13)
	self.response.out.write(form_hw2_rot13 % {"ROT13": self.convertRot13(text)} )
  	

  def get(self):
	self.write_form()
	#self.response.out.write(self.request)

  def post(self):
	text = self.request.get("text")
	self.write_form(text)


import re

description_signup = """
<b>HW2: Signup</b><br><br> 
Fill in several fiends.<br>
Form should say "Hello, username" if the several checks are ok:<br>
 - password is the same in 2 fields<br>
 - username size: 3-20<br>
 - password size: 3-20<br>
 - username without spaces   <br><br>
"""

form_hw2_signup = """

<form method="post">
It is HW2.<br>
We will check password and e-mail.<br>
<label>Username\t<input name="username" value=%(username)s></label>
<span style="color: red">%(username_error)s</span><br>
<label>Password\t<input name="password" type="password"></label>
<span style="color: red">%(password_error)s</span><br>
<label>Verify Password\t<input name="verify" type="password"></label>
<span style="color: red">%(verify_error)s</span><br>
<label>Email(optional)\t<input name="email" value=%(email)s></label>
<span style="color: red">%(email_error)s</span><br>
<input type="submit">
</form>

"""

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE    = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


class Hw2signup_welcome(webapp2.RequestHandler):
  def get(self):
	username=cgi.escape(self.request.get("username"))
	self.response.out.write("Welcome, %s!" % username)

class Hw2signup(webapp2.RequestHandler):

  def valid_username(self, val):
  	if not val:
		return "Username is not specified" 
  	if not USERNAME_RE.match(val):
		return "Username is not valid" 
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

  def write_form(self, username="", email="", 
                       username_error="", password_error="", 
		               verify_error="", email_error=""):
	
	self.response.out.write(description_signup)
	self.response.out.write(form_hw2_signup % {"username": username, 
	                                           "email": email,
	                                           "username_error" : username_error,
	                                           "password_error" : password_error,
	                                           "verify_error"   : verify_error,
	                                           "email_error"    : email_error} )
  	
  def get(self):
	self.write_form()

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
		self.write_form(cgi.escape(username), cgi.escape(email), 
		                username_check, password_check, 
		                verify_check, email_check)
	else:
		self.redirect("hw2_signup/welcome?username="+cgi.escape(username))
		# ?username="+cgi.escape(username))


                     
                          

app = webapp2.WSGIApplication(
                               [('/hw2_rot13', Hw2rot13),
                                ('/hw2_signup', Hw2signup),
                                ('/hw2_signup/welcome', Hw2signup_welcome)],
                               debug=True)

app.run()

