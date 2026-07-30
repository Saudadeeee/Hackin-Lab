FROM php:8.2-apache

# curl for the compose healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Bake the single shared secret the gadgets are meant to reach.
# It lives OUTSIDE the document root and outside the bind-mount so it is only
# reachable by successfully triggering a deserialization gadget.
RUN mkdir -p /var/secret \
 && echo 'POI_SECRET{d0_n0t_unserialize_untrusted_input}' > /var/secret/flag.txt \
 && chmod 644 /var/secret/flag.txt

# Level 8 (Phar deserialization) needs to WRITE a crafted .phar at runtime,
# which requires phar.readonly to be off. Scratch dir for the built archives.
RUN echo 'phar.readonly=Off' > /usr/local/etc/php/conf.d/poi-phar.ini \
 && mkdir -p /tmp/poi_phar \
 && chmod 1777 /tmp/poi_phar

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html/ /tmp/poi_phar

EXPOSE 80
