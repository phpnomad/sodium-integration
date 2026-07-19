<?php

namespace PHPNomad\Sodium\EncryptionIntegration\Tests\Unit;

use PHPNomad\Encryption\Exceptions\DecryptionFailedException;
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\Models\EncryptedValue;
use PHPNomad\Sodium\EncryptionIntegration\Strategies\LegacySecretboxEncryptionStrategy;
use PHPUnit\Framework\TestCase;

class LegacySecretboxEncryptionStrategyTest extends TestCase
{
    public function test_decrypts_raw_secretbox_ciphertext(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox('proprietary-value', $nonce, $key);

        $strategy = new LegacySecretboxEncryptionStrategy(new ArrayKeyProvider([1 => $key]));
        $value = new EncryptedValue($ciphertext, $nonce, 1, LegacySecretboxEncryptionStrategy::CIPHER);

        $this->assertSame('proprietary-value', $strategy->decrypt($value));
    }

    public function test_round_trip(): void
    {
        $strategy = new LegacySecretboxEncryptionStrategy(new ArrayKeyProvider([1 => random_bytes(32)]));

        $encrypted = $strategy->encrypt('value');

        $this->assertSame(LegacySecretboxEncryptionStrategy::CIPHER, $encrypted->getCipher());
        $this->assertSame('value', $strategy->decrypt($encrypted));
    }

    public function test_wrong_key_fails(): void
    {
        $encrypted = (new LegacySecretboxEncryptionStrategy(new ArrayKeyProvider([1 => random_bytes(32)])))
            ->encrypt('value');

        $this->expectException(DecryptionFailedException::class);
        (new LegacySecretboxEncryptionStrategy(new ArrayKeyProvider([1 => random_bytes(32)])))
            ->decrypt($encrypted);
    }
}
