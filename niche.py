import datetime
import hashlib

import web

urls = (
    '/?', 'index',
    '/link/(\d+)', 'link',
    '/link/(\d+)/hide', 'hide_link',
    '/link/(\d+)/close', 'close_link',
    '/comment/(\d+)/delete', 'delete_comment',
    '/comment/(\d+)/like', 'like_comment',
    '/user/([^/]+)', 'user',
    '/login', 'login',
    '/newuser', 'newuser',
)

db = web.database(dbn='mysql', user='niche', pw='whatever', db='niche')

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

class config:
    DATE_FORMAT = '%B %d, %Y'

class model:
    def is_admin(self):
        return True

    def to_datestr(self, timestamp):
        return '%s' % self.to_date(timestamp).strftime(config.DATE_FORMAT)

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

render = web.template.render('templates/',
                             base='layout',
                             globals={ 'model': model() }
                             )

app = web.application(urls, globals())

class index:
    def GET(self):
        links = db.select('1_links', limit=50, order="timestamp DESC")
        return render.index(links)

class link:
    def GET(self, id):
        link = check_found(model().get_link(id))
        return render.link(link)

class hide_link:
    def GET(self, id):
        link = check_found(model().get_link(id))
        db.update('1_links', where='linkID = $id', hidden=not link.hidden, vars={'id': id})

        raise web.seeother('/link/%s' % id)

class close_link:
    def GET(self, id):
        link = check_found(model().get_link(id))
        db.update('1_links', where='linkID = $id', closed=not link.closed, vars={'id': id})

        raise web.seeother('/link/%s' % id)

class delete_comment:
    def GET(self, id):
        comment = check_found(model().get_comment(id))
        db.delete('1_comments', where='commentID = $id', vars={'id': id})

        raise web.seeother('/link/%s' % comment.linkID)

class like_comment:
    def GET(self, id):
        comment = check_found(model().get_comment(id))

        db.insert('1_likes', commentID=comment.commentID, userID=1)
        raise web.seeother('/link/%s' % comment.linkID)

class user:
    def GET(self, id):
        user = first_or_none('1_users', 'username', id)
        return render.user(user)

class login:
    def GET(self):
        return render.login()

if __name__ == "__main__":
    app.run()
