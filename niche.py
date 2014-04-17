#!/usr/bin/python

import datetime
import hashlib
import ConfigParser
import passlib
import markdown
import re
import time
import subprocess
import calendar
import gc
import collections
import json
import random

import web
import bleach
from passlib.apps import custom_app_context as pwd_context

import strings
import utils
import version

# pylint: disable=redefined-builtin
# pylint: disable=redefined-outer-name
# pylint: disable=no-init

urls = (
    r'/?', 'index',
    r'/links(/\d+)?(/\d+)?(/\d+)?', 'links',
    r'/link/new', 'new_link',
    r'/link/(\d+)', 'link',
    r'/link/(\d+)/hide', 'hide_link',
    r'/link/(\d+)/close', 'close_link',
    r'/link/(\d+)/new', 'new_comment',
    r'/comment/(\d+)/delete', 'delete_comment',
    r'/comment/(\d+)/like', 'like_comment',
    r'/user/([^/]+)', 'user',
    r'/user/([^/]+)/links', 'user_links',
    r'/user/([^/]+)/comments', 'user_comments',
    r'/user/([^/]+)/checkout', 'checkout',
    r'/user/([^/]+)/password', 'password',
    r'/user/([^/]+)/edit', 'user_edit',
    r'/login', 'login',
    r'/logout', 'logout',
    r'/newuser', 'newuser',
    r'/rss', 'rss',
    r'/debug/counters', 'debug_counters',

    # MonkeyFilter compatible URLs.
    r'/link\.php/(\d+)', 'link',
    r'/user\.php/([^/]+)', 'user',
    r'/rss.php', 'rss',
    r'/rss.xml', 'rss',
)

ALLOWED_TAGS = """
a abbr acronym b blockquote br
code em i ol ul li p
pre quote small strike strong
u img
""".replace('\n', ' ').strip().split()

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'abbr': ['title'],
    'acronym': ['title'],
    'img': ['src', 'alt'],
}

# Default configuration.
DEFAULTS = [
    ( 'general', {
            'dateformat': '%B %d, %Y',
            'base': '/',
            'extra_tags': '',
            'limit': 50,
            'server_type': 'dev',
            'user_fields': 'realname email homepage gravatar_email team location twitter facebook google_plus_ skype aim',
            'history_days': 7,
            }),
    ( 'groups', {
            'admins': '',
            }),
    ( 'db', {
            'db': 'niche',
            'user': 'niche',
            'password': 'whatever',
            }),
    ( 'site', {
            'name': 'Nichefilter',
            'subtitle': 'of no fixed subtitle',
            'contact': None,
            'license': None,
            'secret': '',
            }),
    ]

counters = utils.Counters()

class Config(ConfigParser.RawConfigParser):
    def set_defaults(self, defaults):
        for section, items in defaults:
            self.add_section(section)

            for name, value in items.items():
                self.set(section, name, value)

    def getlist(self, section, option):
        return self.get(section, option).split()

def read_config():
    """Set up the defaults and read in niche.ini, if any."""
    cfg = Config()
    cfg.set_defaults(DEFAULTS)
    cfg.read('niche.ini')
    return cfg

config = read_config()

FEATURES = 'likes gravatar rss checkout'.split()

def get_features(config):
    features = web.utils.Storage()

    for feature in FEATURES:
        features[feature] = config.has_option('features', feature) and config.getboolean('features', feature)

    return features

features = get_features(config)

def get_version():
    return version.__version__

def get_string(id):
    """Get a string gettext style.  Splits the strings from the
    code.
    """
    id = id.lower()
    id = re.sub(r'[\']', '', id)
    id = re.sub(r'\W', '_', id)
    id = re.sub(r'_{2,}', '_', id)
    id = re.sub(r'_$', '', id)
    return strings.__dict__[id]

_ = get_string

db = web.database(dbn='mysql',
                  user=config.get('db', 'user'),
                  pw=config.get('db', 'password'),
                  db=config.get('db','db'),
                  )

def require_feature(name):
    if not features[name]:
        raise web.notfound()

def now():
    return time.time()

fallbacks = {
    'user': web.utils.Storage(username='anonymous'),
}

class JSONMapper:
    def __init__(self, around, name):
        self._around = around
        self._name = name

        raw = getattr(around, name)
        raw = json.loads(raw) if raw else {}
        self._values = web.storage(raw)

    def __getattr__(self, key):
        return getattr(self._values, key, None)

    def get(self, key):
        return getattr(self._values, key, None)

    def set(self, key, value):
        if value != getattr(self, key):
            self._values[key] = value
            encoded = json.dumps(self._values)
            db.update('1_users', where='userID = $id', contacts=encoded, vars={'id': self._around.userID})

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

        if name.endswith('_json'):
            field = name[:-5]
            mapper = JSONMapper(self, field)
            setattr(self, name, mapper)
            return mapper

        if name.endswith('s'):
            singular = name[:-1]
            table = '1_%s' % name
            assert self._type
            key = '%sID' % self._type

            rows = db.select(table, where='%s = $id' % key, vars={'id': getattr(self, key)})
            return [AutoMapper(singular, x) for x in rows]

        raise AttributeError(name)

    def get(self, key):
        return getattr(self, key, None)

    def has(self, key):
        return key in self._around

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

def map_all(type, results):
    return [AutoMapper(type, x) for x in results]

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

def linkify(text):
    return bleach.clean(bleach.linkify(text, parse_email=True))

def render_input(v, use_markdown=False):
    """Tidy up user input and insert breaks for empty lines."""
    tags = ALLOWED_TAGS + config.getlist('general', 'extra_tags')
    attrs = ALLOWED_ATTRIBUTES

    if use_markdown:
        return bleach.clean(
            markdown.markdown(v, output_format='html5'),
            tags=tags, attributes=attrs)
    else:
        v = bleach.clean(v, tags=tags, attributes=attrs)
        out = ''

        for line in v.split('\n'):
            if not line.strip():
                out += '<br/>\n'
            else:
                out += line + '\n'

        return out

class Model:
    """Top level helpers.  Exposed to scripts."""
    def is_admin(self):
        id = session.get('userID', None)
        return id != None and (str(id) in config.getlist('groups', 'admins'))

    def is_user_or_admin(self, user_id):
        id = session.get('userID', None)

        if id is None:
            return False
        elif id == user_id:
            return True
        else:
            return self.is_admin()

    def get_link(self, id):
        """Get a link by link ID"""
        return first_or_none('link', 'linkID', id)

    def get_comment(self, id):
        """Get a comment by comment ID"""
        return first_or_none('comment', 'commentID', id, strict=True)

    def get_user(self, id):
        """Get a user by user ID"""
        return first_or_none('user', 'userID', id)

    def get_user_by_name(self, name):
        """Get a user by user name"""
        return first_or_none('user', 'username', name)

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

    def paginate(self, offset, total, per_page):
        # TODO(michaelh): really a helper, not part of the model.
        page = 1 + offset // per_page
        pages = total // per_page
        step = 1
        for step in (1, 2, 5, 10, 20, 50):
            if pages / step <= 6:
                break
        if pages > 1:
            indexes = set([1, 2, pages, pages-1, page] + range(step, pages, step))
            if page > 1:
                indexes.add(page-1)
            if page < pages:
                indexes.add(page+1)
        else:
            indexes = []
        return page, sorted(indexes)

    def to_rss_date(self, timestamp):
        return datetime.datetime.fromtimestamp(timestamp).strftime('%a, %d %b %Y %H:%M:%S +0000')

    def field_text(self, name):
        return get_string('field_%s' % name)

    def plural(self, value, name):
        # I appoligise in advance.
        if value == 1:
            return '%s %s' % (value, name)
        else:
            return '%d %ss' % (value, name)

    def get_new(self):
        since = now() - 60*60*24*config.get('general', 'history_days')
        comments = db.select('1_comments', where='timestamp >= $since AND userID <> $user', order='timestamp ASC', limit=50, vars={'since': since, 'user': session.get('userID', None)})
        # Pull out the unique links.
        ids = {}
        for comment in comments:
            if comment.linkID not in ids:
                ids[comment.linkID] = comment
        comments = sorted(ids.values(), key=lambda x: x.linkID)
        return [AutoMapper('comment', x) for x in comments]

model = Model()

render_globals = {
    'model': model,
    'config': config,
    'features': features,
    'version': get_version(),
    'linkify': linkify,
    'render_input': render_input,
}

render = web.template.render(
    'templates/',
    base='layout',
    globals=render_globals,
    )

naked_render = web.template.render(
    'templates/',
    globals=render_globals,
    )

app = web.application(urls, locals())

def get_csrf():
    token = session.get('csrf_token', None)
    if token is None:
        token = hashlib.md5(''.join((
                str(random.randrange(0, 2**20)),
                config.get('site', 'secret'),
                config.get('db', 'db'),
                config.get('db', 'user')))
                            ).hexdigest()
        session.csrf_token = token
    return token

def check_csrf(value):
    expect = session.get('csrf_token', None)

    if value is None or value != expect:
        model.inform(_('Possible cross site request forgery.  Try again.'))
        return False
    else:
        return True

class CSRFInput(web.form.Hidden):
    def __init__(self):
        super(CSRFInput, self).__init__(name='csrf_token')

    def render(self):
        attrs = self.attrs.copy()
        attrs['type'] = self.get_type()
        attrs['value'] = get_csrf()
        attrs['name'] = self.name
        return '<input %s/>' % attrs

    def validate(self, value):
        return check_csrf(value)

TEXT_SIZE = 80
TEXT_MAX_LENGTH = 150

def tidy_form(form):
    for input in form.inputs:
        if not isinstance(input, CSRFInput):
            input.description = get_string('field_%s' % input.name)

        if isinstance(input, web.form.Textbox) or isinstance(input, web.form.Password):
            input.attrs['size'] = TEXT_SIZE
            input.attrs['maxlength'] = TEXT_MAX_LENGTH
    return form

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

def need_user_or_admin(id, msg):
    if not model.is_user_or_admin(id):
        model.inform(msg)
        redirect('/login')            

def check_password(got, user):
    if user is None:
        return False

    try:
        return passlib.hash.mysql323.verify(got, user.password)
    except ValueError:
        return pwd_context.verify(got, user.password)

def error(message, condition, target='/'):
    """Log an error if condition is true and bounce to somewhere."""
    if condition:
        counters.bump('error')
        model.inform(message)
        redirect(target)

def render_links(where=None, span=None, vars={}, date_range=None):
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

    return render.links(map_all('link', links), span, web.ctx.path, offset, limit, total, date_range)

class index:
    def GET(self):
        counters.bump(self)
        return render_links()

class links:
    def GET(self, year, month, day):
        counters.bump(self)

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
            # Work around the year 2038 problem.
            end_year = min(2037, year + 100)
            end = datetime.date(end_year, month, day)
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

        # Pull the oldest and youngest from the database.
        limits = db.query('SELECT MIN(timestamp) as first, MAX(timestamp) as last FROM 1_links')
        limits = limits[0]
        first = datetime.datetime.fromtimestamp(limits.first)
        last = datetime.datetime.fromtimestamp(limits.last)

        date_range = web.utils.Storage(
            years=range(first.year, last.year+1),
            year=None if no_year else year,
            month=None if no_month else month,
            months=calendar.month_name,
            )

        return render_links(
            where='timestamp >= $tstart and timestamp < $tend', 
            vars={ 'tstart': tstart, 'tend': tend },
            span=span,
            date_range=date_range,
            )

class link:
    def GET(self, id):
        counters.bump(self)
        link = model.get_link(id)
        form = new_comment.form()
        return render.link(link, form, False)

class new_link:
    form = web.form.Form(
        web.form.Textbox('title', web.form.notnull),
        web.form.Textbox('url', web.form.Validator(_("Not a URL"), url_validator)),
        web.form.Textbox('url_description'),
        web.form.Textarea('description', rows=5, cols=80),
        web.form.Textarea('extended', rows=5, cols=80),
        web.form.Checkbox('use_markdown', value='use_markdown'),
        CSRFInput(),
        validators = [
            web.form.Validator(_("URLs need a description"), lambda x: x.url_description if x.url else True),
            web.form.Validator(_("Need a URL or description"), lambda x: x.url or x.description),
            ]
        )
    form = tidy_form(form)

    def authenticate(self):
        authenticate(_("Login to post"))

    def GET(self):
        self.authenticate()
        return render.new_link(self.form(), None)

    def POST(self):
        counters.bump(self)
        self.authenticate()

        form = self.form()

        if not form.validates():
            return render.new_link(form, None)

        user = model.get_active()
        markdown = form.d.use_markdown
        url_description = render_input(form.d.url_description, markdown)
        description = render_input(form.d.description, markdown)
        extended = render_input(form.d.extended, markdown)

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
        counters.bump(self)
        link = model.get_link(id)
        need_admin(_('Admin needed to hide a link'))

        next = not link.hidden
        db.update('1_links', where='linkID = $id', hidden=next, vars={'id': id})

        model.inform(_("Link is hidden") if next else _("Link now shows"))
        redirect('/link/%s' % id)

class close_link:
    def GET(self, id):
        counters.bump(self)
        link = model.get_link(id)

        need_admin(_('Admin needed to close a link'))
        next = not link.closed
        db.update('1_links', where='linkID = $id', closed=next, vars={'id': id})

        model.inform(_("Link is closed") if next else _("Link is open"))
        redirect('/link/%s' % id)

class new_comment:
    form = web.form.Form(
        web.form.Textarea('comment', web.form.notnull, rows=5, cols=80),
        web.form.Checkbox('use_markdown', value='use_markdown'),
        CSRFInput(),
        )
    form = tidy_form(form)

    def check(self, id):
        authenticate(_("Login to comment"))
        link = model.get_link(id)

        error(_("Link is closed"), link.closed)

        return link

    def POST(self, id):
        counters.bump(self)
        link = self.check(id)
        form = self.form()

        if not form.validates():
            return render.link(link, form, None)

        user = model.get_active()
        comment = render_input(form.d.comment, form.d.use_markdown)

        if 'preview' in web.input():
            return render.link(link, form, comment)

        db.insert('1_comments',
                  linkID=link.linkID,
                  userID=user.userID,
                  timestamp=now(),
                  content=comment
                  )
        model.inform(_("New comment success"))
        redirect('/link/%d' % link.linkID)

class delete_comment:
    def GET(self, id):
        counters.bump(self)
        comment = model.get_comment(id)

        need_admin(_('Admin needed to delete a comment'))
        db.delete('1_comments', where='commentID = $id', vars={'id': id})

        model.inform(_("Comment deleted"))
        redirect('/link/%s' % comment.linkID)

class like_comment:
    def GET(self, id):
        counters.bump(self)
        # TODO: CSRF.
        require_feature('likes')
        authenticate(_("Login to like"))
        comment = model.get_comment(id)

        userID = session.userID
        db.insert('1_likes', commentID=comment.commentID, userID=userID)

        model.inform(_("Liked"))
        redirect('/link/%s' % comment.linkID)

class user:
    def GET(self, id):
        counters.bump(self)
        user = first('user', 'username', id)
        return render.user(user)

class user_links:
    def GET(self, id):
        counters.bump(self)
        user = first('user', 'username', id)
        return render_links(where='userID=$id', vars={'id': user.userID})

class user_comments:
    def GET(self, id):
        counters.bump(self)
        user = first('user', 'username', id)
        comments = db.select('1_comments', where='userID=$id', order='timestamp DESC',
                             vars={'id': user.userID},
                             limit=config.get('general', 'limit'))
        return render.user_comments([AutoMapper('comment', x) for x in comments])

class checkout:
    def GET(self, name):
        counters.bump(self)
        require_feature('checkout')
        user = model.get_user_by_name(name)
        need_user_or_admin(user.userID, _('Only the user can checkout their links'))

        web.header('Content-Type', 'application/xml')
        return naked_render.rss(user.links, web.ctx.home)

class login:
    login = web.form.Form(
        web.form.Textbox('username', web.form.notnull),
        web.form.Password('password', web.form.notnull),
        CSRFInput(),
        )
    login = tidy_form(login)

    def GET(self):
        return render.login(self.login())

    def POST(self):
        counters.bump(self)
        form = self.login()

        if not form.validates():
            return render.login(form)

        user = first_or_none('user', 'username', form.d.username)

        if not check_password(form.d.password, user):
            counters.bump(self, 'fail')
            form.valid = False
            model.inform(_("Bad username or password"))
            return render.login(form)

        session.userID = user.userID

        model.inform(_("Logged in"))
        counters.bump(self, 'ok')
        redirect('/')

class logout:
    def GET(self):
        counters.bump(self)
        session.userID = None

        model.inform(_("Logged out"))
        redirect('/')

class password:
    form = web.form.Form(
        web.form.Password('password', web.form.notnull),
        web.form.Password('new_password', web.form.notnull, password_validator),
        web.form.Password('again', web.form.notnull),
        CSRFInput(),
        validators=[
            web.form.Validator(_("Passwords don't match"), lambda x: x.new_password == x.again)
            ]
        )
    form = tidy_form(form)

    def authenticate(self, name):
        authenticate()

        target = model.get_user_by_name(name)
        need_user_or_admin(target.userID, _('Permission denied'))
        return target

    def GET(self, name):
        self.authenticate(name)
        return render.password(self.form())

    def POST(self, name):
        counters.bump(self)
        target = self.authenticate(name)
        form = self.form()

        if not form.validates():
            return render.password(form)

        if not model.is_admin():
            if not check_password(form.d.password, target):
                counters.bump(self, 'bad_password')
                form.note = _('Bad password')
                return render.password(form)

        db.update('1_users', password=pwd_context.encrypt(form.d.new_password), where='userID=$id', vars={'id': target.userID})
        
        model.inform(_("Password changed"))
        redirect('/user/%s' % name)

class user_edit:
    def make_form(self, user):
        names = config.getlist('general', 'user_fields')
        values = user.contacts_json

        def get(name):
            value = values.get(name)
            return value if value else user.get(name)

        fields = [web.form.Textbox(x, value=get(x), size=60) for x in names]
        fields.append(web.form.Textarea('bio', rows=5, cols=80, value=get('bio')))
        fields.append(CSRFInput())
        return tidy_form(web.form.Form(*fields))

    def get_target(self, name):
        authenticate()
        target = model.get_user_by_name(name)
        need_user_or_admin(target.userID, _('Permission denied'))
        return target

    def GET(self, name):
        target = self.get_target(name)
        form = self.make_form(target)
        return render.user_edit(target, form)

    def POST(self, username):
        counters.bump(self)
        target = self.get_target(username)
        form = self.make_form(target)

        if not form.validates():
            return render.user_edit(target, form)

        names = config.getlist('general', 'user_fields')
        values = target.contacts_json

        for name in names:
            if target.has(name):
                db.update('1_users', where='userID = $id', vars={'id': target.userID}, **{name: form[name].value})
            else:
                values.set(name, form[name].value)

        bio = render_input(form.d.bio)
        db.update('1_users', bio=bio, where='userID = $id', vars={'id': target.userID})
        redirect('/user/%s' % username)


class rss:
    def GET(self):
        counters.bump(self)
        require_feature('rss')
        links = db.select('1_links', order='linkID DESC', limit=20)
        links = map_all('link', links)
        web.header('Content-Type', 'application/xml')
        return naked_render.rss(links, web.ctx.home)


class debug_counters:
    def GET(self):
        counters.bump(self)
        need_admin('Only admins can access server status pages.')
        web.header('Content-Type', 'application/json')
        return json.dumps(counters.get_snapshot())


def main():
    server_type = config.get('general', 'server_type')

    if server_type == 'fastcgi':
        web.wsgi.runwsgi = lambda func, addr=None: web.wsgi.runfcgi(func, addr)
    elif server_type == 'dev':
        # Development machine.  Run stand alone
        pass
    else:
        raise ValueError('Unhandled server_type "%s"' % server_type)

    app.run()

if __name__ == "__main__":
    main()
