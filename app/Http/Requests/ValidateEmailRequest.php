<?php
namespace App\Http\Requests;use Illuminate\Foundation\Http\FormRequest;
final class ValidateEmailRequest extends FormRequest { public function authorize():bool{return true;} public function rules():array{return ['email'=>['required','string'],'enable_company_lookup'=>['sometimes','boolean'],'disposable_domains'=>['sometimes','array'],'disposable_domains.*'=>['string'],'role_based_prefixes'=>['sometimes','array'],'role_based_prefixes.*'=>['string']];}}
