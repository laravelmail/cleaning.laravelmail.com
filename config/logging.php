<?php
return ['default'=>env('V2_LOG_CHANNEL','stack'),'channels'=>['stack'=>['driver'=>'stack','channels'=>['single'],'ignore_exceptions'=>false],'single'=>['driver'=>'single','path'=>storage_path('logs/v2.log'),'level'=>env('V2_LOG_LEVEL','info'),'replace_placeholders'=>true]]];
