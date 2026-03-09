FROM php:8.2-apache
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-dev && rm -rf /var/lib/apt/lists/*
RUN docker-php-ext-install pdo pdo_sqlite
RUN mkdir -p /var/db
COPY . /var/www/html/
# Initialize database on build (runs as root, creates /var/db/idor_lab.db)
RUN php /var/www/html/init_db.php
# Fix ownership AFTER database is created so www-data can write to it
RUN chown -R www-data:www-data /var/www/html/ /var/db/ && chmod 755 /var/db/
EXPOSE 80
