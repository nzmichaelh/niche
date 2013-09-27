#!/usr/bin/python

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
import utils

urls = (
    '/?', 'index',
    '/links(/\d+)?(/\d+)?(/\d+)?', 'links',
    '/link/new', 'new_link',
    '/link/(\d+)', 'link',
    '/link/(\d+)/hide', 'hide_link',
    '/link/(\d+)/close', 'close_link',
    '/link/(\d+)/new', 'new_comment',
    '/comment/(\d+)/delete', 'delete_comment',
    '/comment/(\d+)/like', 'like_comment',
    '/user/([^/]+)', 'user',
    '/user/([^/]+)/links', 'user_links',
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
            'wsgi': 'false',
            'limit': 50,
            }),
    ( 'db', {
            'db': 'niche',
            'user': 'niche',
            'password': 'whatever',
            }),
    ( 'site', {
            'name': 'Nichefilter',
            'subtitle': 'of no fixed subtitle',
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

FEATURES = 'likes'.split()

def get_features(config):
    features = web.utils.Storage()

    for feature in FEATURES:
        features[feature] = config.has_option('features', feature) and config.getboolean('features', feature)

    return features

features = get_features(config)

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


def require_feature(name):
    if not features[name]:
        raise web.notfound()

def now():
    return time.time()

fallbacks = {
    'user': web.utils.Storage(username='anonymous'),
}

class AutoMapper:
    def __init__(self, type, around):
        self._type = type
        self._around = around

    def __getattr__(self, name):
        if hasattr(self._around, name):
            return getattr(self._around, name)

        key = '%sID' % name

        if hasattr(self._around, key):
            id = getattr(self._around, key)
            got = first_or_none(name, key, id)

            if got:
                return got

            if name in fallbacks:
                return fallbacks[name]

            raise web.notfound()

        if name.endswith('s'):
            singular = name[:-1]
            table = '1_%s' % name
            assert self._type
            key = '%sID' % self._type

            rows = db.select(table, where='%s = $id' % key, vars={'id': getattr(self, key)})
            return [AutoMapper(singular, x) for x in rows]

        raise AttributeError(name)

    def ago(self):
        return utils.ago(self.timestamp)

    def to_date(self):
        """Convert a timestamp to a date object."""
        return datetime.date.fromtimestamp(self.timestamp)

    def to_datestr(self):
        """Convert a timestamp to a date string."""
        return self.to_date().strftime(config.get('general', 'dateformat'))

    def to_date_link(self):
        """Convert a timestamp to a link."""
        date = self.to_date()
        return '%04d/%02d/%02d' % (date.year, date.month, date.day)

def first_or_none(type, column, id, strict=False):
    """Get the first item in the table that matches or None if there's
    no match.
    """
    table = '1_%ss' % type
    vs = db.select(table, where='%s = $id' % column, vars={'id': id}, limit=1)

    if len(vs):
        return AutoMapper(type, vs[0])
    elif strict:
        raise web.notfound()
    else:
        return None

def first(type, column, id):
    """Get the first matching item in the table or raise not found."""
    return first_or_none(type, column, id, strict=True)

class Model:
    """Top level helpers.  Exposed to scripts."""
    def is_admin(self):
        id = session.get('userID', None)
        return id != None and id <= 2

    def get_link(self, id):
        """Get a link by link ID"""
        return first_or_none('link', 'linkID', id)

    def get_comment(self, id):
        """Get a comment by comment ID"""
        return first_or_none('comment', 'commentID', id, strict=True)

    def get_user(self, id):
        """Get a user by user ID"""
        return first_or_none('user', 'userID', id)

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

        return first_or_none('user', 'userID', id)

model = Model()

render = web.template.render('templates/',
                             base='layout',
                             globals={ 'model': model, 'config': config, 'features': features },
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

# Validate a password.  Pretty lax.
password_validator = web.form.Validator(_("Short password"), lambda x: len(x) >= 3)

def url_validator(v):
    if not v:
        return True

    return re.match('(http|https|ftp|mailto)://.+', v)

def redirect(url):
    """Bounce to a different site absolute URL."""
    raise web.seeother(url)

def authenticate(msg=_("Login required")):
    if not session.get('userID', None):
        model.inform(msg)
        redirect('/login')            

def need_admin(msg):
    if not model.is_admin():
        model.inform(msg)
        redirect('/login')            

def error(message, condition, target='/'):
    """Log an error if condition is true and bounce to somewhere."""
    if condition:
        model.inform(message)
        redirect(target)

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

def render_links(where=None, span=None, vars={}):
    input = web.input()
    offset = int(input.get('offset', 0))
    offset = max(offset, 0)

    limit = int(input.get('limit', config.get('general', 'limit')))
    limit = max(0, min(200, limit))

    links = db.select('1_links', where=where, vars=vars, limit=limit, offset=offset, order="timestamp DESC")

    if where:
        results = db.query("SELECT COUNT(*) AS total FROM 1_links WHERE %s" % where, vars=vars)
    else:
        results = db.query("SELECT COUNT(*) AS total FROM 1_links")

    total = results[0].total

    return render.links([AutoMapper('link', x) for x in links], span, web.ctx.path, offset, limit, total)
    
class index:
    def GET(self):
        return render_links()

class links:
    def GET(self, year, month, day):
        def tidy(v, low, high):
            """Turn an optional parameter into a validated number"""
            if v:
                v = int(v[1:])
                if v < low or v > high:
                    raise web.notfound()

                return False, v
            else:
                return True, low

        no_year, year = tidy(year, 1990, 2037)
        no_month, month = tidy(month, 1, 12)
        no_day, day = tidy(day, 1, 31)

        start = datetime.date(year, month, day)
        span = None

        # Figure out the span based on what was supplied
        if no_year:
            end = datetime.date(year + 100, month, day)
            span = 'years'
        elif no_month:
            end = datetime.date(year + 1, month, day)
            span = 'months'
        elif no_day:
            if month == 12:
                end = datetime.date(year + 1, 1, day)
            else:
                end = datetime.date(year, month + 1, day)
        else:
            end = start + datetime.timedelta(days=1)

        tstart = time.mktime(start.timetuple())
        tend = time.mktime(end.timetuple())

        return render_links(where='timestamp >= $tstart and timestamp < $tend', 
                          vars={ 'tstart': tstart, 'tend': tend }, span=span)

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
        redirect('/link/%d' % next)

class hide_link:
    def GET(self, id):
        link = model.get_link(id)
        next = not link.hidden
        db.update('1_links', where='linkID = $id', hidden=next, vars={'id': id})

        model.inform(_("Link is hidden") if next else _("Link now shows"))
        redirect('/link/%s' % id)

class close_link:
    def GET(self, id):
        link = model.get_link(id)
        next = not link.closed
        db.update('1_links', where='linkID = $id', closed=next, vars={'id': id})

        model.inform(_("Link is closed") if next else _("Link is open"))
        redirect('/link/%s' % id)

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
        return render.link(link, self.form(), None)

    def POST(self, id):
        link = self.check(id)
        form = self.form()

        if not form.validates():
            return render.link(link, form, None)

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
        redirect('/link/%d' % link.linkID)

class delete_comment:
    def GET(self, id):
        comment = model.get_comment(id)

        need_admin(_('Admin needed to delete a comment'))
        db.delete('1_comments', where='commentID = $id', vars={'id': id})

        model.inform(_("Comment deleted"))
        redirect('/link/%s' % comment.linkID)

class like_comment:
    def GET(self, id):
        check_feature('likes')
        authenticate(_("Login to like"))
        comment = model.get_comment(id)

        userID = session.userID
        db.insert('1_likes', commentID=comment.commentID, userID=userID)

        model.inform(_("Liked"))
        redirect('/link/%s' % comment.linkID)

class user:
    def GET(self, id):
        user = first('user', 'username', id)
        return render.user(user)

class user_links:
    def GET(self, id):
        user = first('user', 'username', id)
        return render_links(where='userID=$id', vars={'id': user.userID})

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

        user = first_or_none('user', 'username', form.d.username)
        ok = False

        if user:
            try:
                ok = passlib.hash.mysql323.verify(form.d.password, user.password)
            except ValueError:
                ok = pwd_context.verify(form.d.password, user.password)

        if not ok:
            form.valid = False
            model.inform(_("Bad username or password"))
            return render.login(form)

        session.userID = user.userID

        model.inform(_("Logged in"))
        redirect('/')

class logout:
    def GET(self):
        session.userID = None

        model.inform(_("Logged out"))
        redirect('/')

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
        redirect('/user/%s' % id)

if __name__ == "__main__":
    if config.getboolean('general', 'wsgi'):
        web.config.debug = False
        web.wsgi.runwsgi = lambda func, addr=None: web.wsgi.runfcgi(func, addr)
    else:
        # Development machine.  Run stand alone
        pass

    app.run()
