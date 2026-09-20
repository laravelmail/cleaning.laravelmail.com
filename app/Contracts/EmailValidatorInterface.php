<?php
namespace App\Contracts;
interface EmailValidatorInterface { public function validate(string $email, array $disposableDomains, array $rolePrefixes, bool $companyLookup): array; }
