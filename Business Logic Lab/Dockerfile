FROM php:8.2-apache

COPY . /var/www/html/

# Every learner gets a JSON state document under state/. The directory has to
# be writable by the web user; shop.php falls back to the system temp dir if a
# read-only bind mount ever makes that impossible.
RUN mkdir -p /var/www/html/state \
 && chown -R www-data:www-data /var/www/html \
 && chmod 777 /var/www/html/state

EXPOSE 80
