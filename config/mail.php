<?php
return ['default'=>env('V2_MAIL_MAILER','log'),'mailers'=>['log'=>['transport'=>'log','channel'=>env('V2_MAIL_LOG_CHANNEL')]],'from'=>['address'=>env('V2_MAIL_FROM_ADDRESS','check@yourdomain.com'),'name'=>env('V2_MAIL_FROM_NAME','Validation V2')]];
