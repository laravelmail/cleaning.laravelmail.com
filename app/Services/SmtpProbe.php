<?php
namespace App\Services;
use App\Contracts\SmtpProbeInterface;use Illuminate\Support\Facades\Cache;use Illuminate\Support\Facades\Log;
final class SmtpProbe implements SmtpProbeInterface {
 public function verify(string $email,string $domain):array{return $this->probe($email,$domain);}
 public function catchAll(string $domain):?bool{return Cache::remember("v2:catchall:$domain",3600,function()use($domain):?bool{$r=$this->probe('xprobe_'.bin2hex(random_bytes(7)).'@'.$domain,$domain);$c=$r['code'];if(in_array($c,[250,251],true))return true;if(in_array($c,[450,451,452,550,551,552,553],true))return false;return null;});}
 private function probe(string $email,string $domain):array{usleep((int)(max(1.2,min(2.5,$this->gaussian(1.8,.3)))*1_000_000));$hosts=[];$weights=[];if(!getmxrr($domain,$hosts,$weights))return ['valid'=>false,'code'=>null];array_multisort($weights,SORT_ASC,$hosts);$socket=null;try{$timeout=(int)config('validation_v2.smtp_timeout',6);$socket=@stream_socket_client('tcp://'.$hosts[0].':25',$errno,$errstr,$timeout);if(!$socket)return ['valid'=>false,'code'=>null];stream_set_timeout($socket,$timeout);$this->read($socket);$from=(string)config('validation_v2.smtp_check_from');$helo=explode('@',$from,2)[1]??'emailvalidator.com';$this->command($socket,"HELO $helo\r\n");$this->command($socket,"MAIL FROM:<$from>\r\n");$reply=$this->command($socket,"RCPT TO:<$email>\r\n");$code=preg_match('/^(\d{3})/',$reply,$m)?(int)$m[1]:null;return ['valid'=>in_array($code,[250,251],true),'code'=>$code];}catch(\Throwable $e){Log::debug('V2 SMTP probe failed',['domain'=>$domain,'exception'=>$e::class]);return ['valid'=>false,'code'=>null];}finally{if(is_resource($socket)){@fwrite($socket,"QUIT\r\n");@fclose($socket);}}}
 private function command($socket,string $command):string{fwrite($socket,$command);return $this->read($socket);}
 private function read($socket):string{$reply='';while(($line=fgets($socket,515))!==false){$reply.=$line;if(strlen($line)<4||$line[3]!=='-')break;}return $reply;}
 private function gaussian(float $mean,float $sd):float{$u=max(mt_rand()/mt_getrandmax(),1e-12);$v=mt_rand()/mt_getrandmax();return $mean+$sd*sqrt(-2*log($u))*cos(2*M_PI*$v);}
}
