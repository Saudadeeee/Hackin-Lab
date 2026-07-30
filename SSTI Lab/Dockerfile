FROM php:8.2-apache

# Bake the secret the higher levels disclose. It lives OUTSIDE the web root
# (and outside the ./ volume mount) so it is only reachable via the SSTI
# file-read / RCE vectors, never by direct URL.
RUN mkdir -p /var/secret \
 && printf 'SSTI_LAB_SECRET{server_side_template_injection_pwned}\nIf you can read this through a {{ }} expression, you have achieved SSTI file disclosure.\n' > /var/secret/flag.txt \
 && chmod 644 /var/secret/flag.txt

# Copy the lab source (redundant when the compose volume is mounted, but keeps
# the image runnable on its own).
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
