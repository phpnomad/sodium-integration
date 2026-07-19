<?php

namespace PHPNomad\Sodium\EncryptionIntegration\Tests\Unit;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\ValueObjects\EncryptedValue;
use PHPNomad\Sodium\EncryptionIntegration\Strategies\SodiumEncryptionStrategy;
use PHPUnit\Framework\TestCase;

class SodiumEncryptionStrategyTest extends TestCase
{
    private function strategy(bool $fallback = false, ?ArrayKeyProvider $keys = null): SodiumEncryptionStrategy
    {
        $keys ??= new ArrayKeyProvider([1 => random_bytes(32)]);

        return new SodiumEncryptionStrategy($keys, $fallback);
    }

    public function test_encrypt_decrypt_round_trip(): void
    {
        $strategy = $this->strategy();

        $encrypted = $strategy->encrypt('sk-live-super-secret');

        $this->assertSame(EncryptedValue::CIPHER_XCHACHA, $encrypted->getCipher());
        $this->assertNotSame('sk-live-super-secret', $encrypted->getCiphertext());
        $this->assertSame('sk-live-super-secret', $strategy->decrypt($encrypted));
    }

    public function test_each_encryption_uses_a_fresh_nonce(): void
    {
        $strategy = $this->strategy();

        $a = $strategy->encrypt('same-plaintext');
        $b = $strategy->encrypt('same-plaintext');

        $this->assertNotSame($a->getNonce(), $b->getNonce());
        $this->assertNotSame($a->getCiphertext(), $b->getCiphertext());
    }

    public function test_aead_context_binds_ciphertext(): void
    {
        $strategy = $this->strategy();

        $encrypted = $strategy->encrypt('secret', 'tenant:42:column:token');

        // Correct context decrypts.
        $this->assertSame('secret', $strategy->decrypt($encrypted, 'tenant:42:column:token'));

        // A different context must fail — the value cannot be replayed elsewhere.
        $this->expectException(DecryptionFailedException::class);
        $strategy->decrypt($encrypted, 'tenant:99:column:token');
    }

    public function test_tampered_ciphertext_fails_authentication(): void
    {
        $strategy = $this->strategy();
        $encrypted = $strategy->encrypt('secret');

        $bytes = $encrypted->getCiphertext();
        $bytes[0] = $bytes[0] === "\x00" ? "\x01" : "\x00";
        $tampered = new EncryptedValue($bytes, $encrypted->getNonce(), 1, EncryptedValue::CIPHER_XCHACHA);

        $this->expectException(DecryptionFailedException::class);
        $strategy->decrypt($tampered);
    }

    public function test_wrong_key_fails(): void
    {
        $encryptKeys = new ArrayKeyProvider([1 => random_bytes(32)]);
        $decryptKeys = new ArrayKeyProvider([1 => random_bytes(32)]);

        $encrypted = (new SodiumEncryptionStrategy($encryptKeys))->encrypt('secret');

        $this->expectException(DecryptionFailedException::class);
        (new SodiumEncryptionStrategy($decryptKeys))->decrypt($encrypted);
    }

    public function test_key_rotation_encrypts_with_current_decrypts_against_stored(): void
    {
        $v1 = random_bytes(32);
        $v2 = random_bytes(32);

        // Value sealed under v1 while v1 was current.
        $v1Strategy = new SodiumEncryptionStrategy(new ArrayKeyProvider([1 => $v1], 1));
        $sealedUnderV1 = $v1Strategy->encrypt('old-value');
        $this->assertSame(1, $sealedUnderV1->getKeyVersion());

        // Rotate: v2 is now current, but v1 is still held for old ciphertext.
        $ring = new ArrayKeyProvider([1 => $v1, 2 => $v2], 2);
        $rotated = new SodiumEncryptionStrategy($ring);

        // New writes use v2...
        $sealedUnderV2 = $rotated->encrypt('new-value');
        $this->assertSame(2, $sealedUnderV2->getKeyVersion());

        // ...and both old and new values still decrypt.
        $this->assertSame('new-value', $rotated->decrypt($sealedUnderV2));
        $this->assertSame('old-value', $rotated->decrypt($sealedUnderV1));
    }

    public function test_legacy_secretbox_value_decrypts_with_fallback_enabled(): void
    {
        $key = random_bytes(32);

        // Simulate a value written the OLD way: sodium_crypto_secretbox at v1,
        // stored with no cipher marker (CIPHER_UNKNOWN).
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $legacyCiphertext = sodium_crypto_secretbox('legacy-secret', $nonce, $key);
        $legacyValue = new EncryptedValue($legacyCiphertext, $nonce, 1, EncryptedValue::CIPHER_UNKNOWN);

        $strategy = new SodiumEncryptionStrategy(new ArrayKeyProvider([1 => $key]), true);

        $this->assertSame('legacy-secret', $strategy->decrypt($legacyValue));
    }

    public function test_legacy_secretbox_value_fails_without_fallback(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $legacyValue = new EncryptedValue(
            sodium_crypto_secretbox('legacy-secret', $nonce, $key),
            $nonce,
            1,
            EncryptedValue::CIPHER_UNKNOWN
        );

        $strategy = new SodiumEncryptionStrategy(new ArrayKeyProvider([1 => $key]), false);

        $this->expectException(DecryptionFailedException::class);
        $strategy->decrypt($legacyValue);
    }

    public function test_new_and_legacy_values_coexist_under_fallback(): void
    {
        $key = random_bytes(32);
        $strategy = new SodiumEncryptionStrategy(new ArrayKeyProvider([1 => $key]), true);

        // A modern AEAD value...
        $modern = $strategy->encrypt('modern');

        // ...and a legacy secretbox value, both readable by the same strategy.
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $legacy = new EncryptedValue(
            sodium_crypto_secretbox('legacy', $nonce, $key),
            $nonce,
            1,
            EncryptedValue::CIPHER_UNKNOWN
        );

        $this->assertSame('modern', $strategy->decrypt($modern));
        $this->assertSame('legacy', $strategy->decrypt($legacy));
    }
}
