FROM php:8.2-apache

# curl PHP extension (for the curl-based levels) + iproute2 (to add the
# link-local metadata IP to loopback at startup)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcurl4-openssl-dev iproute2 \
    && docker-php-ext-install curl \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite

# Baked secret for Level 6 (file:// read) — lives OUTSIDE the web root
RUN mkdir -p /var/secret \
    && echo 'FLAG{ssrf_file_scheme}' > /var/secret/flag6.txt \
    && echo 'ssrf-lab internal filesystem — not served over HTTP' > /var/secret/README.txt \
    && chmod 644 /var/secret/flag6.txt /var/secret/README.txt

# Allow the docroot .htaccess (metadata rewrite) to take effect
RUN printf '\n<Directory /var/www/html>\n    AllowOverride All\n    Options FollowSymLinks\n</Directory>\n' >> /etc/apache2/apache2.conf

# Startup: add the cloud-metadata link-local address to loopback so the mock
# metadata service (169.254.169.254) is reachable only from inside the box,
# then hand off to Apache.
RUN printf '#!/bin/bash\nip addr add 169.254.169.254/32 dev lo 2>/dev/null || true\nexec apache2-foreground\n' > /usr/local/bin/ssrf-start.sh \
    && chmod +x /usr/local/bin/ssrf-start.sh

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html/

EXPOSE 80
CMD ["/usr/local/bin/ssrf-start.sh"]
