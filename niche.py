import datetime
import hashlib
import ConfigParser
import passlib
import re
import time

import web
import bleach
from passlib.apps import custom_app_context as pwd_context

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

# Default configuration
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
    ( 'site', {
            'name': 'Nichefilter'
            }),
    ]

def read_config():
    """Set up the defaults and read in niche.ini, if any."""
    cfg = ConfigParser.RawConfigParser()

    for section, items in DEFAULTS:
        cfg.add_section(section)

        for name, value in items.items():
            cfg.set(section, name, value)

    cfg.read('niche.ini')
    return cfg

config = read_config()

def get_string(id):
    """Get a string gettext style.  Splits the strings from the
    code.
    """
    id = id.lower().replace(' ', '_').replace("'", "")
    return strings.__dict__[id]

_ = get_string

db = web.database(dbn='mysql',
                  user=config.get('db', 'user'),
                  pw=config.get('db', 'password'),
                  db=config.get('db','db')
                  )

def first_or_none(table, column, id, strict=False):
    """Get the first item in the table that matches or None if there's
    no match.
    """
    vs = db.select(table, where='%s = $id' % column, vars={'id': id}, limit=1)

    if len(vs):
        return vs[0]
    elif strict:
        raise web.notfound()
    else:
        return None

def first(table, column, id):
    """Get the first matching item in the table or raise not found."""
    return first_or_none(table, column, id, strict=True)

class Model:
    """Top level helpers.  Exposed to scripts."""
    def is_admin(self):
        return True

    def ago(self, timestamp):
        """Turn a timestamp into a string saying how long ago the
        timestamp was.
        """
        elapsed = now() - timestamp
        elapsed = max(1, elapsed)

        seconds = elapsed
        minutes = seconds / 60
        hours = minutes / 60
        days = hours / 24
        weeks = days / 7
        months = days / 30.5
        years = days / 365

        if seconds < 60:
            v, suffix = seconds, 'second'
        elif minutes <= 60:
            v, suffix = minutes, 'minute'
        elif hours <= 48:
            v, suffix = hours, 'hour'
        elif days <= 14:
            v, suffix = days, 'day'
        elif weeks < 12:
            v, suffix = weeks, 'week'
        elif months < 24:
            v, suffix = months, 'month'
        else:
            v, suffix = years, 'years'

        v = int(v)

        if v != 1:
            return '%s %ss' % (v, suffix)
        else:
            return '%s %s' % (v, suffix)

    def to_datestr(self, timestamp):
        """Convert a timestamp to a date string."""
        return self.to_date(timestamp).strftime(config.get('general', 'dateformat'))

    def to_date(self, timestamp):
        """Convert a timestamp to a date object."""
        return datetime.date.fromtimestamp(timestamp)

    def to_date_link(self, timestamp):
        """Convert a timestamp to a link."""
        date = self.to_date(timestamp)
        return '%02d/%02d/%04d' % (date.day, date.month, date.year)

    def get_link(self, id):
        """Get a link by link ID"""
        return first_or_none('1_links', 'linkID', id, strict=True)

    def get_comment(self, id):
        """Get a comment by comment ID"""
        return first_or_none('1_comments', 'commentID', id, strict=True)

    def get_user(self, id):
        """Get a user by user ID"""
        return first_or_none('1_users', 'userID', id)

    def get_comments(self, id, key='linkID'):
        """Get all comments for a link or other"""
        return db.select('1_comments', where='%s = $id' % key, vars={'id': id})

    def get_likes(self, id, key='commentID'):
        """Get all likes for a comment or other"""
        return db.select('1_likes', where='%s = $id' % key, vars={'id': id})

    def get_links(self, id, key='userID'):
        """Get all links for a user or other"""
        return db.select('1_links', where='%s = $id' % key, vars={'id': id})

    def get_gravatar(self, email):
        """Get the gravatar hash for an email"""
        return hashlib.md5(email.strip().lower()).hexdigest()

    def get_message(self):
        """Get the message for the user, if any, and clear"""
        message = session.get('message', None)

        if message:
            session.message = None

        return message

    def inform(self, message):
        """Log a message to show the user on the next page"""
        session.message = message

    def get_active(self):
        """Get the user entry for the currently logged in user, or
        None.
        """
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
    """Helper that makes the session object, even if in debug mode."""
    if web.config.get('_session') is None:
        session = web.session.Session(app, web.session.DiskStore('sessions'),
                                      initializer={'message': None}
                                      )
        web.config._session = session
    else:
        session = web.config._session

    return session

session = make_session()

def now():
    """Return the current time in the right epoch."""
    return time.time()

# Validate a password.  Pretty lax.
password_validator = web.form.Validator(_("Short password"), lambda x: len(x) >= 3)

def url_validator(v):
    if not v:
        return True

    return re.match('(http|https|ftp|mailto)://.+', v)

def authenticate(msg=_("Login required")):
    if not session.get('userID', None):
        model.inform(msg)
        raise web.seeother('/login')            

def error(message, condition, target='/'):
    """Log an error if condition is true and bounce to somewhere."""
    if condition:
        model.inform(message)
        raise web.seeother(target)

def render_input(v):
    """Tidy up user input and insert breaks for empty lines."""
    v = bleach.clean(v)
    
    out = ''

    for line in v.split('\n'):
        if not line.strip():
            out += '<br/>\n'
        else:
            out += line + '\n'

    return out

class index:
    def GET(self):
        links = db.select('1_links', limit=50, order="timestamp DESC")
        return render.index(links)

class link:
    def GET(self, id):
        link = model.get_link(id)
        return render.link(link, None, False)

class new_link:
    form = web.form.Form(
        web.form.Textbox('title', web.form.notnull),
        web.form.Textbox('url', web.form.Validator(_("Not a URL"), url_validator)),
        web.form.Textbox('url_description'),
        web.form.Textarea('description', rows=10, cols=80),
        web.form.Textarea('extended', rows=10, cols=80),
        validators = [
            web.form.Validator(_("URLs need a description"), lambda x: x.url_description if x.url else True),
            web.form.Validator(_("Need a URL or description"), lambda x: x.url or x.description),
            ]
        )

    def authenticate(self):
        authenticate(_("Login to post"))

    def GET(self):
        self.authenticate()
        return render.new_link(self.form(), None)

    def POST(self):
        self.authenticate()

        form = self.form()

        if not form.validates():
            return render.new_link(form, None)

        user = model.get_active()
        url_description = render_input(form.d.url_description)
        description = render_input(form.d.description)
        extended = render_input(form.d.extended)

        if 'preview' in web.input():
            preview = web.utils.Storage(
                title=form.d.title,
                URL=form.d.url,
                URL_description=url_description,
                description=description,
                extended=extended)

            return render.new_link(form, preview)

        next = db.insert('1_links',
                         userID=user.userID,
                         timestamp=now(),
                         title=form.d.title,
                         URL=form.d.url,
                         URL_description=url_description,
                         description=description,
                         extended=extended
                         )

        model.inform(_("New post success"))
        return web.seeother('/link/%d' % next)

class hide_link:
    def GET(self, id):
        link = model.get_link(id)
        next = not link.hidden
        db.update('1_links', where='linkID = $id', hidden=next, vars={'id': id})

        model.inform(_("Link is hidden") if next else _("Link now shows"))
        raise web.seeother('/link/%s' % id)

class close_link:
    def GET(self, id):
        link = model.get_link(id)
        next = not link.closed
        db.update('1_links', where='linkID = $id', closed=next, vars={'id': id})

        model.inform(_("Link is closed") if next else _("Link is open"))
        raise web.seeother('/link/%s' % id)

class new_comment:
    form = web.form.Form(
        web.form.Textarea('content', web.form.notnull, rows=10, cols=80)
        )

    def check(self, id):
        authenticate(_("Login to comment"))
        link = model.get_link(id)

        error(_("Link is closed"), link.closed)

        return link

    def GET(self, id):
        link = self.check(id)
        return render.link(link, self.form())

    def POST(self, id):
        link = self.check(id)
        form = self.form()

        if not form.validates():
            return render.link(link, form, False)

        user = model.get_active()
        content = render_input(form.d.content)

        if 'preview' in web.input():
            return render.link(link, form, content)

        next = db.insert('1_comments',
                         linkID=link.linkID,
                         userID=user.userID,
                         timestamp=now(),
                         content=content
                         )

        model.inform(_("New comment success"))
        return web.seeother('/link/%d' % link.linkID)

class delete_comment:
    def GET(self, id):
        comment = model.get_comment(id)
        db.delete('1_comments', where='commentID = $id', vars={'id': id})

        model.inform(_("Comment deleted"))
        raise web.seeother('/link/%s' % comment.linkID)

class like_comment:
    def GET(self, id):
        authenticate(_("Login to like"))
        comment = model.get_comment(id)

        userID = session.userID
        db.insert('1_likes', commentID=comment.commentID, userID=userID)

        model.inform(_("Liked"))
        raise web.seeother('/link/%s' % comment.linkID)

class user:
    def GET(self, id):
        user = first('1_users', 'username', id)
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

class password:
    form = web.form.Form(
        web.form.Password('password', web.form.notnull, password_validator,
                          description=_("New password")),
        web.form.Password('again', web.form.notnull, description=_("Password again")),
        validators=[
            web.form.Validator(_("Passwords don't match"), lambda x: x.password == x.again)
            ]
        )

    def authenticate(self, id):
        authenticate()

        active = model.get_active()
        error(_("Permission denied"), active.username != id, '/user/%s' % id)

    def GET(self, id):
        self.authenticate(id)
        return render.password(self.form())

    def POST(self, id):
        self.authenticate(id)

        form = self.form()

        if not form.validates():
            return render.login(form)

        db.update('1_users', password=pwd_context.encrypt(form.d.password), where='username=$id', vars={'id': id})
        
        model.inform(_("Password changed"))
        raise web.seeother('/user/%s' % id)

if __name__ == "__main__":
    app.run()
