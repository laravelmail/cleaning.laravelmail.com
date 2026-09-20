<?php
namespace App\Http\Requests;use Illuminate\Foundation\Http\FormRequest;
final class CsvRequest extends FormRequest { public function authorize():bool{return true;} public function rules():array{return ['files'=>['required','array','min:1'],'files.*'=>['file','mimes:csv,txt','max:10240'],'email_column'=>['nullable','string'],'gmail_only'=>['sometimes','boolean'],'enable_company_lookup'=>['sometimes','boolean']];}}
