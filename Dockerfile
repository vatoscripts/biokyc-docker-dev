FROM php:7.4-fpm
COPY app/. /var/www/
EXPOSE 9000