import time

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
        v, suffix = years, 'years'

    v = int(v)

    if v != 1:
        return '%s %ss' % (v, suffix)
    else:
        return '%s %s' % (v, suffix)
