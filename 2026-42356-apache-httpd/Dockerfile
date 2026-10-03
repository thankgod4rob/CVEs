FROM httpd:2.4.68

# Enable CGI module and the default cgi-bin ScriptAlias
RUN sed -i \
    -e 's/#LoadModule cgid_module/LoadModule cgid_module/' \
    -e 's/#LoadModule cgi_module/LoadModule cgi_module/' \
    -e 's|#ScriptAlias /cgi-bin/|ScriptAlias /cgi-bin/|' \
    /usr/local/apache2/conf/httpd.conf

COPY cgi-bin/redirect.cgi /usr/local/apache2/cgi-bin/redirect.cgi
COPY cgi-bin/payload       /usr/local/apache2/cgi-bin/payload

RUN chmod 755 /usr/local/apache2/cgi-bin/redirect.cgi \
              /usr/local/apache2/cgi-bin/payload
