<?php
namespace App\Contracts;
interface DomainInspectorInterface { public function registrableDomain(string $value): ?string; public function hasMx(string $domain): bool; public function mxProvider(string $domain): string; public function age(string $domain): array; public function organisation(string $domain): string; }
