<?php
return [
 'smtp_check_from'=>env('V2_SMTP_CHECK_FROM_EMAIL','noreply@emailvalidator.com'),
 'dns_timeout'=>(int)env('V2_DNS_TIMEOUT_SECONDS',3),'smtp_timeout'=>(int)env('V2_SMTP_TIMEOUT_SECONDS',6),
 'max_batch'=>(int)env('V2_MAX_BATCH',10000),'max_concurrent'=>(int)env('V2_MAX_CONCURRENT',300),
 'disposable_domains'=>array_values(array_filter(array_map('trim',explode(',',env('V2_DISPOSABLE_DOMAINS','mailinator.com,10minutemail.com,guerrillamail.com,trashmail.com,tempmail.com,yopmail.com'))))),
 'role_prefixes'=>array_values(array_filter(array_map('trim',explode(',',env('V2_ROLE_PREFIXES','admin,support,info,sales,contact,webmaster,help'))))),
];
