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
# and add the IPv6 wildcard listener (this image's default `Listen 80` binds
# IPv4 only, which left the [::1] spelling of loopback unreachable even though
# internal.php explicitly trusts it and level 4 advertises it). Then hand off
# to Apache. Both steps are skipped harmlessly where unsupported.
RUN printf '#!/bin/bash\nip addr add 169.254.169.254/32 dev lo 2>/dev/null || true\nif ip -6 addr show lo 2>/dev/null | grep -q "::1"; then grep -q "Listen .::.:80" /etc/apache2/ports.conf || echo "Listen [::]:80" >> /etc/apache2/ports.conf; fi\nexec apache2-foreground\n' > /usr/local/bin/ssrf-start.sh \
    && chmod +x /usr/local/bin/ssrf-start.sh

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html/

EXPOSE 80
CMD ["/usr/local/bin/ssrf-start.sh"]
