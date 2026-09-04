FROM php:8.2-apache

# pdo_sqlite backs the lab's data store. It ships enabled in the official
# image; the guard keeps the build green if that ever changes.
RUN php -m | grep -qi pdo_sqlite || docker-php-ext-install pdo_sqlite

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html \
 && mkdir -p /var/www/html/data \
 && chown -R www-data:www-data /var/www/html/data \
 && chmod 777 /var/www/html/data

EXPOSE 80
