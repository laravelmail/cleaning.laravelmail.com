FROM composer:2.8 AS vendor
WORKDIR /app
COPY composer.json composer.lock* ./
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader --ignore-platform-reqs
FROM php:8.3-cli-alpine
RUN apk add --no-cache libzip-dev oniguruma-dev && docker-php-ext-install mbstring
WORKDIR /app
COPY --from=vendor /app/vendor ./vendor
COPY . .
RUN mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs && chown -R www-data:www-data storage
USER www-data
EXPOSE 8080
CMD ["php","artisan","serve","--host=0.0.0.0","--port=8080"]
