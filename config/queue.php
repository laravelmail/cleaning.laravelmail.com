<?php
return ['default'=>env('V2_QUEUE_CONNECTION','sync'),'connections'=>['sync'=>['driver'=>'sync']],'failed'=>['driver'=>'null']];
