# Notice

**I have verified that this still works, but I haven't made any efforts to
document it or keep it updated.  If you want to run it or send me patches then
that is fine.

Please remember the Library is from Pat Winn and it may be best to look around
to see if he has more modern code rather than starting with this.**




I made a daemon for this with Pat Winn's php code.  I'm not sure if I made any
modifications to his files so I'm leaving them in the php directory as well.

The daemon listens on 9595 and sends the request to the DHCP server.  It sends
the response back as a json element.

Making a daemon was needed because if you want to access a low port in UNIX
you need to be root (or privileged at least).  That's not available with php
running under apache.  Even if it was, I wouldn't want to permit all PHP
applications to access udp port 67.

While I was looking for attribution I stumbled on this post to dhcp-hackers
which shows Pat based his modules on some perl code.  Funny since I had
intended to use his code to write the perl version.

https://lists.isc.org/pipermail/dhcp-hackers/2010-June/001863.html

My current intentions are to rewrite the daemon in perl (a language I think is
better suited for daemon work than php-cli, but that may just be because I'm
more comfortable with it)

I want the daemon to support sending queries to multiple DHCP servers at the
same time.  Whichever DHCP server responds positively first will be the
response sent to the requester.

