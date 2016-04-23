#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class Post(db.Model):
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainHandler(Handler):

    def get(self):
        self.redirect('/blog/newpost')



class NewPostHandler(Handler):

    def render_front(self,  subject="", content="", error=""):
	    posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")	   
	    self.render("bloginput.html", subject=subject, content=content, error=error, posts=posts)

    def get(self):
        self.render('bloginput.html')

#the browser has sent a post request.
#This method will respond.
    def post(self):
            #"get" the "subject" from the request object received from the form which is
            #posting the request
	    subject = self.request.get("subject")
	    content = self.request.get("content")

	    if  subject and content:
		    p = Post(subject=subject, content=content)
		    p.put()
		    p_id = str(p.key().id())
		    self.redirect('/blog/%s' % p_id)
	    else:
		    error = 'Need to enter both subject and content'
		    self.render_front(subject=subject, content=content, error=error)

class PostHandler(Handler):
    def render_front(self, post_id, post):
	    #posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
	    
	    self.render("post.html", post_id=post_id, post=post)

    def get(self, post_id):
            p = Post.get_by_id(int(post_id))
            self.render_front(post_id, p)


class BlogHandler(Handler):
        def render_front(self):
	    posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
	    self.render("posts.html", posts=posts)

	def get(self):
                self.render_front()
        

	    
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/([0-9]+)', PostHandler),
    ('/blog', BlogHandler)
], debug=True)
