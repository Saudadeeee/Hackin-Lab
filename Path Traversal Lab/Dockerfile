FROM php:8.2-apache
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/secret /var/log/ptlab /var/www/html/files /var/www/html/pages /var/www/html/docs /var/www/html/logs

# Create 10 individual flag files in /var/secret/
RUN echo "FLAG{basic_path_traversal}" > /var/secret/level1_flag.txt
RUN echo "FLAG{lfi_basic_include}" > /var/secret/level2_flag.txt
RUN echo "FLAG{php_filter_wrapper}" > /var/secret/level3_flag.txt
RUN echo "FLAG{double_traverse_bypass}" > /var/secret/level4_flag.txt
RUN echo "FLAG{extension_check_bypass}" > /var/secret/level5_flag.txt
RUN echo "FLAG{log_file_traversal}" > /var/secret/level6_flag.txt
RUN echo "FLAG{base64_filter_exfil}" > /var/secret/level7_flag.txt
RUN echo "FLAG{useless_check_bypass}" > /var/secret/level8_flag.txt
RUN echo "FLAG{proc_self_environ}" > /var/secret/level9_flag.txt
RUN echo "FLAG{multilayer_traversal_master}" > /var/secret/level10_flag.txt
RUN chmod 644 /var/secret/*.txt

# Create decoy/accessible files
RUN echo "Welcome to Path Traversal Lab! This is a public file." > /var/www/html/files/welcome.txt
RUN echo "README: Files in this directory are public." > /var/www/html/files/readme.txt
RUN echo "Info page content here." > /var/www/html/files/info.txt
RUN echo "<h1>Home</h1><p>Welcome to our site.</p>" > /var/www/html/pages/home.php
RUN echo "<h1>About</h1><p>About our company.</p>" > /var/www/html/pages/about.php

# Create log file with flag for level 6 (log poisoning simulation)
RUN echo "2024-01-01 00:00:00 - System startup\n2024-01-01 00:01:00 - FLAG{log_file_traversal} - Access log initialized" > /var/log/ptlab/access.log
RUN chmod 644 /var/log/ptlab/access.log

# Create symlink for level 8
RUN ln -s /var/secret /var/www/html/secret_files_backup

COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html/
EXPOSE 80
