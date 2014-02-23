import collections
import copy
import time
import threading


class Counters(object):
    def __init__(self):
        self.counters = collections.defaultdict(int)
        self.lock = threading.Lock()
        self.counters['id'] = id(self)

    def bump(self, name, arg=None):
        if not isinstance(name, str):
            name = name.__class__.__name__
            if '.' in name:
                name = name[name.rindex('.')+1:]
        if arg:
            name = '%s/%s' % (name, arg)

        with self.lock:
            self.counters[name] += 1

    def get_snapshot(self):
        with self.lock:
            return copy.copy(self.counters)


def now():
    """Return the current time in the right epoch."""
    return time.time()

def ago(timestamp):
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
        v, suffix = years, 'year'

    v = int(v)

    if v != 1:
        return '%s %ss' % (v, suffix)
    else:
        return '%s %s' % (v, suffix)
