GET = / \
	/link/2 /link/100 \
	/user/michaelh /user/tracicle \
	/login \
	/rss /rss.php /rss.xml

BASE = http://ch.monkeyfilter.com

ALL = $(GET:%=%-get)

all: $(ALL)

%-get:
	wget -O /dev/null -nv $(BASE)$*
