FROM php:8.2-apache

# ------------------------------------------------------------------
# Baked secrets (outside the web root). A web shell that reads these
# proves real code execution on the box.
# ------------------------------------------------------------------
RUN mkdir -p /var/secret \
 && echo 'FLAG{upload_no_validation}'              > /var/secret/level1_flag.txt \
 && echo 'FLAG{upload_extension_blocklist_bypass}' > /var/secret/level2_flag.txt \
 && echo 'FLAG{upload_mime_bypass}'                > /var/secret/level3_flag.txt \
 && echo 'FLAG{upload_magic_bytes_bypass}'         > /var/secret/level4_flag.txt \
 && echo 'FLAG{upload_double_extension}'           > /var/secret/level5_flag.txt \
 && echo 'FLAG{upload_case_bypass}'                > /var/secret/level6_flag.txt \
 && echo 'FLAG{upload_htaccess}'                   > /var/secret/level7_flag.txt \
 && echo 'FLAG{upload_trailing_bypass}'            > /var/secret/level8_flag.txt \
 && echo 'FLAG{upload_content_filter_bypass}'      > /var/secret/level9_flag.txt \
 && echo 'FLAG{upload_waf_bypass}'                 > /var/secret/level10_flag.txt \
 && printf '%s\n' \
      'Nice shell! Your uploaded PHP executed on the server.' \
      'This is Remote Code Execution via unrestricted file upload.' \
      'The per-level FLAG you are after lives at /var/secret/level<N>_flag.txt' \
      > /var/secret/flag.txt \
 && chmod 644 /var/secret/*.txt

# ------------------------------------------------------------------
# Apache (intentionally vulnerable):
#  - execute uploaded PHP-family files, even with a trailing dot/space
#    or a double extension (mod_mime-style behaviour)
#  - honour uploaded .htaccess overrides inside uploads/  (level 7)
# ------------------------------------------------------------------
RUN printf '%s\n' \
    '<Directory "/var/www/html/uploads">' \
    '    AllowOverride All' \
    '    Require all granted' \
    '    Options +FollowSymLinks' \
    '</Directory>' \
    '<FilesMatch "(?i)\.(php|php3|php4|php5|php7|pht|phtml|phar)([. ]|$)">' \
    '    SetHandler application/x-httpd-php' \
    '</FilesMatch>' \
    > /etc/apache2/conf-enabled/upload-lab.conf \
 && a2enmod mime

# ------------------------------------------------------------------
# App code (also bind-mounted by docker-compose; COPY keeps the image
# runnable standalone). Upload dirs must be writable by the web server.
# ------------------------------------------------------------------
COPY . /var/www/html/
RUN mkdir -p /var/www/html/uploads \
 && for n in 1 2 3 4 5 6 7 8 9 10; do mkdir -p "/var/www/html/uploads/level$n"; done \
 && chown -R www-data:www-data /var/www/html \
 && chmod -R 0777 /var/www/html/uploads

EXPOSE 80
