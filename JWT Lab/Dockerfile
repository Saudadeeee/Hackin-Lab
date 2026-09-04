FROM php:8.2-apache

# pdo_sqlite backs the level-7 key table. It ships enabled in the official
# image; the guard keeps the build green if that ever changes.
RUN php -m | grep -qi pdo_sqlite || docker-php-ext-install pdo_sqlite

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html \
 && chmod -R 755 /var/www/html/keys \
 && mkdir -p /var/www/html/pastes && chown www-data:www-data /var/www/html/pastes

EXPOSE 80
