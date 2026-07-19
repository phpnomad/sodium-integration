<?php

namespace PHPNomad\Sodium\EncryptionIntegration\Strategies;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Exceptions\EncryptionException;
use PHPNomad\Encryption\Interfaces\EncryptionStrategy;
use PHPNomad\Encryption\Interfaces\KeyProvider;
use PHPNomad\Encryption\Models\EncryptedValue;
use SodiumException;
use Throwable;

/**
 * Default cipher for phpnomad/encryption: authenticated encryption with
 * libsodium's XChaCha20-Poly1305 IETF AEAD construction.
 *
 * XChaCha20-Poly1305 is chosen because its 192-bit (24-byte) nonce is large
 * enough to generate at random for every message without birthday-bound
 * collision concerns — no nonce counter or state needs to be persisted. The
 * Poly1305 tag authenticates both the ciphertext and the caller-supplied
 * associated data ($context), so a value cannot be silently swapped between
 * rows, columns, or tenants.
 *
 * Optionally decrypts legacy sodium_crypto_secretbox ciphertext to ease
 * migration from an older secretbox-based store (see the constructor).
 */
final class SodiumEncryptionStrategy implements EncryptionStrategy
{
    /**
     * Cipher discriminator this strategy stamps onto every {@see EncryptedValue}
     * it produces: libsodium's XChaCha20-Poly1305 IETF AEAD. The contract package
     * names no ciphers — this identifier is owned here.
     */
    public const CIPHER = 'xchacha20poly1305_ietf';

    private KeyProvider $keys;
    private bool $allowLegacySecretboxFallback;

    /**
     * @param KeyProvider $keys                         Supplies versioned keys.
     * @param bool        $allowLegacySecretboxFallback When true, values whose
     *        cipher is unknown are first tried as AEAD and, failing that, as
     *        legacy sodium_crypto_secretbox. Leave false for new deployments;
     *        enable only while migrating pre-existing secretbox data.
     */
    public function __construct(KeyProvider $keys, bool $allowLegacySecretboxFallback = false)
    {
        $this->keys = $keys;
        $this->allowLegacySecretboxFallback = $allowLegacySecretboxFallback;
    }

    public function encrypt(string $plaintext, string $context = ''): EncryptedValue
    {
        $version = $this->keys->currentVersion();
        $key = $this->keys->getKey($version);

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                $context,
                $nonce,
                $key
            );
        } catch (Throwable $e) {
            throw new EncryptionException('Encryption failed: ' . $e->getMessage(), 0, $e);
        } finally {
            sodium_memzero($key);
        }

        return new EncryptedValue($ciphertext, $nonce, $version, self::CIPHER);
    }

    public function decrypt(EncryptedValue $value, string $context = ''): string
    {
        $key = $this->keys->getKey($value->getKeyVersion());

        try {
            return $this->decryptWithKey($value, $context, $key);
        } finally {
            sodium_memzero($key);
        }
    }

    /**
     * @throws DecryptionFailedException
     */
    private function decryptWithKey(EncryptedValue $value, string $context, string $key): string
    {
        $cipher = $value->getCipher();

        $plaintext = match ($cipher) {
            self::CIPHER => $this->aeadDecrypt($value, $context, $key),
            LegacySecretboxEncryptionStrategy::CIPHER => $this->secretboxDecrypt($value, $key),
            default => $this->decryptUnknown($value, $context, $key),
        };

        if ($plaintext === false) {
            throw new DecryptionFailedException(
                'Decryption failed: wrong key, mismatched context, or corrupted data.'
            );
        }

        return $plaintext;
    }

    /**
     * Cipher was not recorded with the value. Try AEAD, then (if enabled) the
     * legacy secretbox construction.
     *
     * @return string|false
     */
    private function decryptUnknown(EncryptedValue $value, string $context, string $key)
    {
        $plaintext = $this->aeadDecrypt($value, $context, $key);

        if ($plaintext === false && $this->allowLegacySecretboxFallback) {
            return $this->secretboxDecrypt($value, $key);
        }

        return $plaintext;
    }

    /**
     * @return string|false
     */
    private function aeadDecrypt(EncryptedValue $value, string $context, string $key)
    {
        // Sodium throws on a wrong-sized nonce/key rather than returning false;
        // normalize both outcomes to a soft failure so callers get one exception.
        try {
            return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $value->getCiphertext(),
                $context,
                $value->getNonce(),
                $key
            );
        } catch (SodiumException $e) {
            return false;
        }
    }

    /**
     * @return string|false
     */
    private function secretboxDecrypt(EncryptedValue $value, string $key)
    {
        try {
            return sodium_crypto_secretbox_open(
                $value->getCiphertext(),
                $value->getNonce(),
                $key
            );
        } catch (SodiumException $e) {
            return false;
        }
    }
}
