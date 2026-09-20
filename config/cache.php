<?php
return ['default'=>env('V2_CACHE_STORE','file'),'stores'=>['file'=>['driver'=>'file','path'=>storage_path('framework/cache/data')]],'prefix'=>env('V2_CACHE_PREFIX','validation_v2_cache')];
