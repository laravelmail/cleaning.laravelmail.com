<?php
namespace App\Http\Requests;use Illuminate\Foundation\Http\FormRequest;
final class BatchRequest extends FormRequest { public function authorize():bool{return true;} public function rules():array{return ['emails'=>['required','array','min:1','max:'.config('validation_v2.max_batch')],'emails.*'=>['string'],'enable_company_lookup'=>['sometimes','boolean'],'disposable_domains'=>['sometimes','array'],'role_based_prefixes'=>['sometimes','array']];}}
