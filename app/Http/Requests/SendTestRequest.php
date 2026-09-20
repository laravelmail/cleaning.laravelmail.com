<?php
namespace App\Http\Requests;use Illuminate\Foundation\Http\FormRequest;
final class SendTestRequest extends FormRequest { public function authorize():bool{return true;} public function rules():array{return ['sender_email'=>['required','email'],'sender_password'=>['required','string'],'recipient_email'=>['required','email'],'subject'=>['required','string'],'body'=>['required','string'],'smtp_host'=>['required','string'],'smtp_port'=>['required','integer','between:1,65535']];}}
