FROM php:8.2-apache

# The CSP evaluator and the level-5 effect check parse real HTML with
# DOMDocument, which lives in ext-dom. It ships enabled in the official image;
# the guard keeps the build green if that ever changes.
RUN php -m | grep -qi '^dom$' || docker-php-ext-install dom

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
