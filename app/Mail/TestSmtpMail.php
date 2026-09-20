<?php
namespace App\Mail;use Illuminate\Bus\Queueable;use Illuminate\Mail\Mailable;use Illuminate\Mail\Mailables\Content;use Illuminate\Mail\Mailables\Envelope;use Illuminate\Queue\SerializesModels;
final class TestSmtpMail extends Mailable {use Queueable,SerializesModels;public function __construct(public readonly string $mailSubject,public readonly string $mailBody){}public function envelope():Envelope{return new Envelope(subject:$this->mailSubject);}public function content():Content{return new Content(htmlString:nl2br(e($this->mailBody)));}public function attachments():array{return[];}}
