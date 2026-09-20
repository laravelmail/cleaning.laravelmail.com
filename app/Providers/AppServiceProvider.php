<?php
namespace App\Providers;
use App\Contracts\DomainInspectorInterface;use App\Contracts\EmailValidatorInterface;use App\Contracts\SmtpProbeInterface;use App\Services\DomainInspector;use App\Services\EmailValidationService;use App\Services\SmtpProbe;use Illuminate\Support\ServiceProvider;
final class AppServiceProvider extends ServiceProvider {
 public function register(): void { $this->app->bind(DomainInspectorInterface::class,DomainInspector::class);$this->app->bind(SmtpProbeInterface::class,SmtpProbe::class);$this->app->bind(EmailValidatorInterface::class,EmailValidationService::class); }
 public function boot(): void {}
}
