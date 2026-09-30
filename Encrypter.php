<?php

namespace Voyager\Encryption;

use Voyager\Contracts\Encryption\DecryptException;
use Voyager\Contracts\Encryption\EncryptException;
use Voyager\Contracts\Encryption\Encrypter as EncrypterContract;
use Voyager\Contracts\Encryption\StringEncrypter;

/**
 * Authenticated symmetric encryption over openssl.
 *
 * A CBC cipher carries a separate HMAC; a GCM cipher authenticates itself and carries a tag
 * instead. Either way nothing is decrypted before it is verified. The payload is Laravel's, so
 * what one encrypts under a key the other decrypts.
 */
class Encrypter implements EncrypterContract, StringEncrypter
{
    /**
     * Key length in bytes, and whether the cipher authenticates itself.
     *
     * @var array<string, array{size: int, aead: bool}>
     */
    private const array SUPPORTED = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];

    /** A GCM tag is 16 bytes; openssl would accept a shorter one, and a shorter one is weaker. */
    private const int TAG_LENGTH = 16;

    private readonly string $key;

    private readonly string $cipher;

    /**
     * Keys decryption falls back on, for data encrypted before the key was rotated.
     *
     * @var list<string>
     */
    private array $previous_keys = [];

    /**
     * @throws EncryptException the cipher isn't supported, or the key isn't its length
     */
    public function __construct(#[\SensitiveParameter] string $key, string $cipher = 'AES-256-CBC')
    {
        if (! static::supported($key, $cipher)) {
            throw new EncryptException(self::unsupported());
        }

        $this->key = $key;
        $this->cipher = $cipher;
    }

    /**
     * Is this key the right length for this cipher?
     */
    public static function supported(#[\SensitiveParameter] string $key, string $cipher): bool
    {
        $spec = self::SUPPORTED[strtolower($cipher)] ?? null;

        return ! is_null($spec) && strlen($key) === $spec['size'];
    }

    /**
     * A fresh key of the right length for the cipher.
     */
    public static function generateKey(string $cipher): string
    {
        return random_bytes(self::SUPPORTED[strtolower($cipher)]['size'] ?? 32);
    }

    /**
     * Does this look like something encrypt() produced?
     */
    public static function appearsEncrypted(string $contents): bool
    {
        $payload = json_decode(base64_decode($contents, true) ?: '', true);

        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']);
    }

    /**
     * @throws EncryptException
     */
    public function encrypt(#[\SensitiveParameter] mixed $value, bool $serialize = true): string
    {
        $iv = random_bytes(openssl_cipher_iv_length(strtolower($this->cipher)) ?: 0);
        $tag = '';

        $encrypted = $this->aead()
            ? openssl_encrypt($serialize ? serialize($value) : $value, strtolower($this->cipher), $this->key, 0, $iv, $tag)
            : openssl_encrypt($serialize ? serialize($value) : $value, strtolower($this->cipher), $this->key, 0, $iv);

        if ($encrypted === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $iv = base64_encode($iv);
        $tag = base64_encode($tag);

        // a CBC payload is only as trustworthy as the mac over it; a GCM payload has its own tag
        $mac = $this->aead() ? '' : $this->hash($iv, $encrypted, $this->key);

        $json = json_encode([
            'iv' => $iv,
            'value' => $encrypted,
            'mac' => $mac,
            'tag' => $tag,
        ], JSON_UNESCAPED_SLASHES);

        if (! is_string($json)) {
            throw new EncryptException('Could not encrypt the data.');
        }

        return base64_encode($json);
    }

    /**
     * @throws EncryptException
     */
    public function encryptString(#[\SensitiveParameter] string $value): string
    {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypts with the current key, then with each previous one in turn. A CBC payload is only
     * decrypted by a key its mac proves it was made with.
     *
     * @throws DecryptException
     */
    public function decrypt(string $payload, bool $unserialize = true): mixed
    {
        $payload = $this->validPayload($payload);

        $iv = base64_decode($payload['iv']);
        $tag = $payload['tag'] === '' ? null : base64_decode($payload['tag']);

        if ($this->aead() && strlen($tag ?? '') !== self::TAG_LENGTH) {
            throw new DecryptException('Could not decrypt the data.');
        }

        if (! $this->aead() && ! is_null($tag)) {
            throw new DecryptException('Unable to use tag because the cipher algorithm does not support AEAD.');
        }

        $decrypted = false;
        $verified = false;

        foreach ($this->getAllKeys() as $key) {
            if (! $this->aead()) {
                if (! hash_equals($this->hash($payload['iv'], $payload['value'], $key), $payload['mac'])) {
                    continue;
                }

                $verified = true;
            }

            $decrypted = openssl_decrypt($payload['value'], strtolower($this->cipher), $key, 0, $iv, $tag ?? '');

            if ($decrypted !== false) {
                break;
            }
        }

        if (! $this->aead() && ! $verified) {
            throw new DecryptException('The MAC is invalid.');
        }

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * @throws DecryptException
     */
    public function decryptString(string $payload): string
    {
        return $this->decrypt($payload, false);
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getAllKeys(): array
    {
        return [$this->key, ...$this->previous_keys];
    }

    public function getPreviousKeys(): array
    {
        return $this->previous_keys;
    }

    /**
     * The keys decryption falls back on once the current key fails.
     *
     * @param list<string> $keys
     * @throws EncryptException a key isn't the cipher's length
     */
    public function previousKeys(#[\SensitiveParameter] array $keys): static
    {
        foreach ($keys as $key) {
            if (! static::supported($key, $this->cipher)) {
                throw new EncryptException(self::unsupported());
            }
        }

        $this->previous_keys = array_values($keys);

        return $this;
    }

    /**
     * Read the payload and prove it is well formed before anything is decrypted.
     *
     * @return array{iv: string, value: string, mac: string, tag: string}
     * @throws DecryptException
     */
    private function validPayload(string $payload): array
    {
        $decoded = json_decode(base64_decode($payload, true) ?: '', true);

        if (! is_array($decoded)) {
            throw new DecryptException('The payload is invalid.');
        }

        foreach (['iv', 'value', 'mac'] as $item) {
            if (! isset($decoded[$item]) || ! is_string($decoded[$item])) {
                throw new DecryptException('The payload is invalid.');
            }
        }

        if (isset($decoded['tag']) && ! is_string($decoded['tag'])) {
            throw new DecryptException('The payload is invalid.');
        }

        if (strlen(base64_decode($decoded['iv'], true) ?: '') !== openssl_cipher_iv_length(strtolower($this->cipher))) {
            throw new DecryptException('The payload is invalid.');
        }

        return $decoded + ['tag' => ''];
    }

    /**
     * The HMAC a non-AEAD payload is checked against, under the given key.
     */
    private function hash(string $iv, string $value, #[\SensitiveParameter] string $key): string
    {
        return hash_hmac('sha256', $iv.$value, $key);
    }

    private function aead(): bool
    {
        return self::SUPPORTED[strtolower($this->cipher)]['aead'];
    }

    private static function unsupported(): string
    {
        return 'Unsupported cipher or incorrect key length. Supported ciphers are: '.implode(', ', array_keys(self::SUPPORTED)).'.';
    }
}
