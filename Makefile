version.py: Makefile
	echo __version__ = \'$(shell git describe --always --dirty --long)\' > $@
