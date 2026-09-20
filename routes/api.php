<?php
use App\Http\Controllers\CsvController;use App\Http\Controllers\ExtractController;use App\Http\Controllers\PermutationController;use App\Http\Controllers\SendController;use App\Http\Controllers\ValidationController;use Illuminate\Support\Facades\Route;
Route::prefix('api/v2')->group(function():void{
 Route::post('/validate',[ValidationController::class,'single']);
 Route::post('/validate/batch',[ValidationController::class,'batch']);
 Route::post('/validate/csv',CsvController::class);
 Route::post('/extract/provider-emails',ExtractController::class);
 Route::post('/permutations',PermutationController::class);
 Route::post('/send-test-email',SendController::class);
});
