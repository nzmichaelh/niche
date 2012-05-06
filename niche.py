import datetime
import hashlib
import ConfigParser
import passlib
import re
import time

from passlib.apps import custom_app_context as pwd_context

import web
#web.config.debug = False

import strings

urls = (
    '/?', 'index',
    '/link/new', 'new_link',
    '/link/(\d+)', 'link',
    '/link/(\d+)/hide', 'hide_link',
    '/link/(\d+)/close', 'close_link',
    '/link/(\d+)/new', 'new_comment',
    '/comment/(\d+)/delete', 'delete_comment',
    '/comment/(\d+)/like', 'like_comment',
    '/user/([^/]+)', 'user',
    '/user/([^/]+)/password', 'password',
    '/login', 'login',
    '/logout', 'logout',
    '/newuser', 'newuser',
)

def get_string(id):
    id = id.lower().replace(' ', '_').replace("'", "")
    return strings.__dict__[id]

_ = get_string

DEFAULTS = [
    ( 'general', {
            'dateformat': '%B %d, %Y',
            'base': '/',
            }),
    ( 'db', {
            'db': 'niche',
            'user': 'niche',
            'password': 'whatever',
            }),
    ]

def read_config():
    cfg = ConfigParser.RawConfigParser()

    for section, items in DEFAULTS:
        cfg.add_section(section)

        for name, value in items.items():
            cfg.set(section, name, value)

    cfg.read('niche.ini')
    return cfg

config = read_config()

db = web.database(dbn='mysql',
                  user=config.get('db', 'user'),
                  pw=config.get('db', 'password'),
                  db=config.get('db','db')
                  )

def first_or_none(table, column, id):
    vs = db.select(table, where='%s = $id' % column, vars={'id': id}, limit=1)

    if len(vs):
        return vs[0]
    else:
        return None

def check_found(v):
    if v:
        return v
    else:
        return web.notfound()

class Model:
    def is_admin(self):
        return True

    def to_datestr(self, timestamp):
        return self.to_date(timestamp).strftime(config.get('general', 'dateformat'))

    def to_date(self, timestamp):
        return datetime.date.fromtimestamp(timestamp)

    def to_date_link(self, timestamp):
        date = self.to_date(timestamp)
        return '%02d/%02d/%04d' % (date.day, date.month, date.year)

    def get_link(self, id):
        return first_or_none('1_links', 'linkID', id)

    def get_comment(self, id):
        return first_or_none('1_comments', 'commentID', id)

    def get_user(self, id):
        return first_or_none('1_users', 'userID', id)

    def get_comments(self, id, key='linkID'):
        return db.select('1_comments', where='%s = $id' % key, vars={'id': id})

    def get_likes(self, id, key='commentID'):
        return db.select('1_likes', where='%s = $id' % key, vars={'id': id})

    def get_links(self, id, key='userID'):
        return db.select('1_links', where='%s = $id' % key, vars={'id': id})

    def get_gravatar(self, email):
        return hashlib.md5(email.strip().lower()).hexdigest()

    def get_message(self):
        message = session.get('message', None)

        if message:
            session.message = None

        return message

    def inform(self, message):
        session.message = message

    def get_active(self):
        id = session.get('userID', None)

        if not id:
            return None

        return first_or_none('1_users', 'userID', id)

model = Model()

render = web.template.render('templates/',
                             base='layout',
                             globals={ 'model': model, 'config': config },
                             )

app = web.application(urls, locals())

def make_session():
    if web.config.get('_session') is None:
        session = web.session.Session(app, web.session.DiskStore('sessions'),
                                      initializer={'message': None}
                                      )
        web.config._session = session
    else:
        session = web.config._session

    return session

session = make_session()

class index:
    def GET(self):
        links = db.select('1_links', limit=50, order="timestamp DESC")
        return render.index(links)

class link:
    def GET(self, id):
        link = check_found(model.get_link(id))
        return render.link(link)

def url_validator(v):
    if not v:
        return True

    return re.match('(http|https|ftp|mailto)://.+', v)

def authenticate(msg=_("Login required")):
    if not session.get('userID', None):
        model.inform(msg)
        raise web.seeother('/login')            

def error(message, condition):
    if not condition:
        model.inform(message)
        raise web.seeother('/')

class new_link:
    form = web.form.Form(
        web.form.Textbox('title', web.form.notnull),
        web.form.Textbox('url', web.form.Validator(_("Not a URL"), url_validator)),
        web.form.Textbox('url_description'),
        web.form.Textarea('description'),
        web.form.Textarea('extended'),
        validators = [
            web.form.Validator(_("URLs need a description"), lambda x: x.url_description if x.url else True),
            web.form.Validator(_("Need a URL or description"), lambda x: x.url or x.description),
            ]
        )

    def authenticate(self):
        authenticate(_("Login to post"))

    def GET(self):
        self.authenticate()
        return render.new_link(self.form())

    def POST(self):
        self.authenticate()

        form = self.form()

        if not form.validates():
            return render.login(form)

        user = model.get_active()
        next = db.insert('1_links',
                         userID=user.userID,
                         timestamp=time.time(),
                         title=form.d.title,
                         URL=form.d.url,
                         URL_description=form.d.url_description,
                         description=form.d.description,
                         extended=form.d.extended
                         )

        model.inform(_("New post success"))
        return web.seeother('/link/%d' % next)

class hide_link:
    def GET(self, id):
        link = check_found(model.get_link(id))
        next = not link.hidden
        db.update('1_links', where='linkID = $id', hidden=next, vars={'id': id})

        model.inform(_("Link is hidden") if next else _("Link now shows"))
        raise web.seeother('/link/%s' % id)

class close_link:
    def GET(self, id):
        link = check_found(model.get_link(id))
        next = not link.closed
        db.update('1_links', where='linkID = $id', closed=next, vars={'id': id})

        model.inform(_("Link is closed") if next else _("Link is open"))
        raise web.seeother('/link/%s' % id)

class new_comment:
    form = web.form.Form(
        web.form.Textarea('content', web.form.notnull)
        )

    def check(self, id):
        authenticate(_("Login to comment"))
        link = model.get_link(id)
        
        error(_("No such link"), link != None)
        error(_("Link is closed"), not link.closed)

        return link

    def GET(self, id):
        link = self.check(id)
        return render.new_comment(link, self.form())

    def POST(self, id):
        link = self.check(id)
        form = self.form()

        if not form.validates():
            return render.new_comment(link, form)

        user = model.get_active()
        next = db.insert('1_comments',
                         linkID=link.linkID,
                         userID=user.userID,
                         timestamp=time.time(),
                         content=form.d.content
                         )

        model.inform(_("New comment success"))
        return web.seeother('/link/%d' % link.linkID)

class delete_comment:
    def GET(self, id):
        comment = check_found(model.get_comment(id))
        db.delete('1_comments', where='commentID = $id', vars={'id': id})

        model.inform(_("Comment deleted"))
        raise web.seeother('/link/%s' % comment.linkID)

class like_comment:
    def GET(self, id):
        comment = check_found(model.get_comment(id))

        db.insert('1_likes', commentID=comment.commentID, userID=1)
        raise web.seeother('/link/%s' % comment.linkID)

class user:
    def GET(self, id):
        user = first_or_none('1_users', 'username', id)
        return render.user(user)

class login:
    login = web.form.Form(
        web.form.Textbox('username', web.form.notnull),
        web.form.Password('password', web.form.notnull),
        )

    def GET(self):
        return render.login(self.login())

    def POST(self):
        form = self.login()

        if not form.validates():
            return render.login(form)

        user = first_or_none('1_users', 'username', form.d.username)

        if not user:
            form.valid = False
            return render.login(form)

        ok = False

        try:
            ok = passlib.hash.mysql323.verify(form.d.password, user.password)
        except ValueError:
            ok = pwd_context.verify(form.d.password, user.password)

        if not ok:
            form.valid = False
            return render.login(form)

        session.userID = user.userID

        model.inform(_("Logged in"))
        raise web.seeother('/')

class logout:
    def GET(self):
        session.userID = None

        model.inform(_("Logged out"))
        raise web.seeother('/')

password_validator = web.form.Validator(_("Short password"), lambda x: len(x) >= 3)

class password:
    form = web.form.Form(
        web.form.Password('password', web.form.notnull, password_validator, description=_("New password")),
        web.form.Password('again', web.form.notnull, description=_("Password again")),
        validators=[
            web.form.Validator(_("Passwords don't match"), lambda x: x.password == x.again)
            ]
        )

    def GET(self, id):
        return render.password(self.form())

    def POST(self, id):
        form = self.form()

        if not form.validates():
            return render.login(form)

        db.update('1_users', password=pwd_context.encrypt(form.d.password), where='username=$id', vars={'id': id})
        
        model.inform(_("Password changed"))
        raise web.seeother('/user/%s' % id)

if __name__ == "__main__":
    app.run()
