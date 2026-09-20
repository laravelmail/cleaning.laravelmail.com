<?php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
if (is_file(dirname(__DIR__).'/.env.v2')) { (new Symfony\Component\Dotenv\Dotenv())->usePutenv()->loadEnv(dirname(__DIR__).'/.env.v2', 'V2_APP_ENV'); }
return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(api: __DIR__.'/../routes/api.php', health: '/up', apiPrefix: '')
    ->withMiddleware(function (Middleware $middleware): void {})
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(fn (Request $request, Throwable $e): bool => $request->is('api/v2/*'));
        $exceptions->render(function (ValidationException $e, Request $request) {
            if (!$request->is('api/v2/*')) return null;
            return response()->json(['ok'=>false,'error'=>['code'=>'validation_failed','message'=>'The request is invalid.','details'=>$e->errors()]], 422);
        });
        $exceptions->render(function (Throwable $e, Request $request) {
            if (!$request->is('api/v2/*')) return null;
            report($e);
            return response()->json(['ok'=>false,'error'=>['code'=>'internal_error','message'=>config('app.debug') ? $e->getMessage() : 'An unexpected error occurred.']], 500);
        });
    })->create();
