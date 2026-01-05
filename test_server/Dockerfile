FROM php:8.1-apache

# Enable SQLite extension
RUN apt-get update && \
    apt-get install -y sqlite3 libsqlite3-dev iputils-ping && \
    docker-php-ext-install pdo pdo_sqlite && \
    rm -rf /var/lib/apt/lists/*

# Copy vulnerable web application
COPY www/ /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html

# Create temp directory for SQLite
RUN mkdir -p /tmp && chmod 777 /tmp

EXPOSE 80

CMD ["apache2-foreground"]
