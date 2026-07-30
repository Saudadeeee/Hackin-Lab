FROM php:8.2-apache

# Bake per-level secrets OUTSIDE the document root so they are only reachable
# through a working XXE (file://, php://filter, OOB, error-based, etc.).
RUN mkdir -p /var/secret \
 && printf '%s' 'FLAG{xxe_file_read}'          > /var/secret/flag1.txt \
 && printf '%s' '<?php /* FLAG{xxe_php_filter} */' > /var/secret/flag2.php \
 && printf '%s' 'FLAG{xxe_blind_oob}'          > /var/secret/flag3.txt \
 && printf '%s' 'FLAG{xxe_error_based}'        > /var/secret/flag4.txt \
 && printf '%s' 'FLAG{xxe_xinclude}'           > /var/secret/flag5.txt \
 && printf '%s' 'FLAG{xxe_svg_upload}'         > /var/secret/flag6.txt \
 && printf '%s' 'FLAG{xxe_encoding_bypass}'    > /var/secret/flag7.txt \
 && printf '%s' 'FLAG{xxe_param_entity_chain}' > /var/secret/flag8.txt \
 && printf '%s' 'FLAG{xxe_waf_bypass}'         > /var/secret/flag10.txt \
 && chmod 644 /var/secret/*

# The document root (including the hosted .dtd files and internal endpoints) is
# bind-mounted over /var/www/html at runtime; COPY keeps the image self-contained.
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
