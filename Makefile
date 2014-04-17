version.py: Makefile
	echo __version__ = \'$(shell git describe --always --dirty --long)\' > $@

DB=$(shell cat niche.ini | grep ^db= | cut -d= -f2)

import: $(wildcard mofi-*.sql.gz)
	zcat $< \
	| sed -r "s# CHARSET\=latin1# CHARSET\=utf8#g" \
	| sed "s#ENGINE=MyISAM##" \
	| mysql -u root -p $(DB)
