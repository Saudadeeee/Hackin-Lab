FROM php:8.2-apache

# Every account, token, message and session in this lab is a row in SQLite.
# pdo_sqlite ships enabled in the official image; the guard keeps the build
# green if that ever changes.
RUN php -m | grep -qi pdo_sqlite || docker-php-ext-install pdo_sqlite

COPY . /var/www/html/

# attacker.hackinlab.internal and collector.hackinlab.internal are "a machine
# you control". Every path on them is answered by collector.php, so a poisoned
# reset link pointing at either name lands in your request log rather than in
# the application. Level 3 needs this.
COPY apache-attacker.conf /etc/apache2/sites-available/zz-attacker.conf
RUN a2ensite zz-attacker && chown -R www-data:www-data /var/www/html

EXPOSE 80
