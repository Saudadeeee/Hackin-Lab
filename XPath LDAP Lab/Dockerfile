FROM php:8.2-apache

# Levels 1-5 evaluate real XPath with DOMDocument/DOMXPath, which come from
# ext-dom and ext-libxml. Both are compiled into the official image; the guard
# keeps the build honest if that ever changes.
RUN php -m | grep -qi '^dom$' \
 && php -m | grep -qi '^libxml$' \
 || (echo 'ext-dom / ext-libxml missing from this PHP build' && exit 1)

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
