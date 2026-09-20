<?php
return [
 'name'=>env('V2_APP_NAME','LaravelMail Validation V2'), 'env'=>env('V2_APP_ENV','production'),
 'debug'=>(bool) env('V2_APP_DEBUG',false), 'url'=>env('V2_APP_URL','http://localhost:8080'),
 'timezone'=>'UTC','locale'=>'en','fallback_locale'=>'en','faker_locale'=>'en_US',
 'key'=>env('V2_APP_KEY'),'cipher'=>'AES-256-CBC',
 'maintenance'=>['driver'=>'file'],
 'providers'=>Illuminate\Support\ServiceProvider::defaultProviders()->merge([App\Providers\AppServiceProvider::class])->toArray(),
];
