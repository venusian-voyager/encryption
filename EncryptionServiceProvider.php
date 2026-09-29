<?php

namespace Voyager\Encryption;

use Voyager\Contracts\Core\FrameworkCore;
use Voyager\NutsAndBolts\DataObjects\Str;
use Voyager\NutsAndBolts\ServiceProvider;
use Laravel\SerializableClosure\SerializableClosure;

class EncryptionServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->registerEncrypter();
        $this->registerSerializableClosureSecurityKey();
    }

    /**
     * The encrypter, on app.key and app.cipher, falling back on app.previous_keys when decrypting.
     */
    protected function registerEncrypter(): void
    {
        $this->app->registerSingleton('encrypter', function (FrameworkCore $app): Encrypter {
            $config = $app->make('config')->get('app');

            return new Encrypter($this->parseKey($config), $config['cipher'])
                ->previousKeys(array_map(
                    fn (string $key): string => $this->parseKey(['key' => $key]),
                    $config['previous_keys'] ?? [],
                ));
        });
    }

    /**
     * Signs serialized closures with the app key, so a worker only runs closures this app made.
     */
    protected function registerSerializableClosureSecurityKey(): void
    {
        $config = $this->app->make('config')->get('app');

        if (! class_exists(SerializableClosure::class) || empty($config['key'])) {
            return;
        }

        SerializableClosure::setSecretKey($this->parseKey($config));
    }

    /**
     * The key itself: a "base64:" key is decoded.
     *
     * @param array<string, mixed> $config
     * @throws MissingAppKeyException
     */
    protected function parseKey(array $config): string
    {
        if (Str::startsWith($key = $this->key($config), $prefix = 'base64:')) {
            $key = base64_decode(Str::after($key, $prefix));
        }

        return $key;
    }

    /**
     * @param array<string, mixed> $config
     * @throws MissingAppKeyException
     */
    protected function key(array $config): string
    {
        $key = $config['key'] ?? null;

        if (! is_string($key) || $key === '') {
            throw new MissingAppKeyException();
        }

        return $key;
    }
}
