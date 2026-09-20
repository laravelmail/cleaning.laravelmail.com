<?php
namespace App\Http\Requests;use Illuminate\Foundation\Http\FormRequest;
final class PermutationRequest extends FormRequest { public function authorize():bool{return true;} public function rules():array{return ['first_name'=>['required','string'],'last_name'=>['required','string'],'nickname'=>['nullable','string'],'domain'=>['required','string'],'validate'=>['sometimes','boolean'],'enable_company_lookup'=>['sometimes','boolean']];}}
