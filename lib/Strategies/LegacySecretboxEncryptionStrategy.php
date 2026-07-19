<?php

namespace PHPNomad\Sodium\EncryptionIntegration\Strategies;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Exceptions\EncryptionException;
use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\Interfaces\KeyProvider;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;
use SodiumException;
use Throwable;

/**
 * Backward-compatibility strategy for data written with libsodium's
 * sodium_crypto_secretbox (XSalsa20-Poly1305).
 *
 * secretbox has no associated-data channel, so the $context argument is
 * accepted for interface compatibility but ignored. Prefer
 * {@see SodiumEncryptionStrategy} for anything new; reach for this only to read
 * (or, if you must, keep writing) an existing secretbox-encrypted corpus.
 */
final class LegacySecretboxEncryptionStrategy implements EncryptionStrategy
{
    private KeyProvider $keys;

    public function __construct(KeyProvider $keys)
    {
        $this->keys = $keys;
    }

    public function encrypt(string $plaintext, string $context = ''): EncryptedValue
    {
        $version = $this->keys->currentVersion();
        $key = $this->keys->getKey($version);

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
        } catch (Throwable $e) {
            throw new EncryptionException('Encryption failed: ' . $e->getMessage(), 0, $e);
        } finally {
            sodium_memzero($key);
        }

        return new EncryptedValue($ciphertext, $nonce, $version, EncryptedValue::CIPHER_SECRETBOX);
    }

    public function decrypt(EncryptedValue $value, string $context = ''): string
    {
        $key = $this->keys->getKey($value->getKeyVersion());

        try {
            $plaintext = sodium_crypto_secretbox_open(
                $value->getCiphertext(),
                $value->getNonce(),
                $key
            );
        } catch (SodiumException $e) {
            $plaintext = false;
        } finally {
            sodium_memzero($key);
        }

        if ($plaintext === false) {
            throw new DecryptionFailedException('Decryption failed: wrong key or corrupted data.');
        }

        return $plaintext;
    }
}
