FROM php:8.2-apache

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html \
 && mkdir -p /var/www/html/state \
 && chown www-data:www-data /var/www/html/state

EXPOSE 80
