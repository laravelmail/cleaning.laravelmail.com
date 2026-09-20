<?php
namespace App\Http\Requests;use Illuminate\Foundation\Http\FormRequest;
final class ExtractRequest extends FormRequest { public function authorize():bool{return true;} public function rules():array{return ['files'=>['required','array','min:1'],'files.*'=>['file','mimes:csv,txt','max:10240'],'providers'=>['sometimes','array'],'providers.*'=>['string','in:gmail,google_workspace,microsoft_365,custom'],'custom_domains'=>['sometimes','array'],'custom_domains.*'=>['string']];}}
