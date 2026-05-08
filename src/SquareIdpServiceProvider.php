<?php

namespace SquareExp\IdpLaravel;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\ServiceProvider;
use SquareExp\IdpLaravel\Middleware\VerifySquareAccessToken;

final class SquareIdpServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/square-idp.php', 'square-idp');

        $this->app->singleton('square-idp', function ($app) {
            return new SquareIdpManager(
                config('square-idp'),
                $app->make(HttpFactory::class),
                $app->make(CacheRepository::class),
            );
        });

        $this->app->alias('square-idp', SquareIdpManager::class);
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/square-idp.php' => config_path('square-idp.php'),
        ], 'square-idp-config');

        $router = $this->app['router'] ?? null;
        if ($router) {
            $router->aliasMiddleware('square.idp', VerifySquareAccessToken::class);
        }
    }
}
