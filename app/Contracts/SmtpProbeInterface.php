<?php
namespace App\Contracts;
interface SmtpProbeInterface { public function verify(string $email, string $domain): array; public function catchAll(string $domain): ?bool; }
