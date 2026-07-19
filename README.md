# phpnomad/sodium-integration

The default [libsodium](https://www.php.net/manual/en/book.sodium.php) cipher
integration for [`phpnomad/encryption`](https://github.com/phpnomad/encryption).
It ships the concrete `EncryptionStrategy` implementations; the contract package
holds only interfaces, value objects, and the framework-agnostic field-level
helpers.

- **`SodiumEncryptionStrategy`** — authenticated encryption with
  XChaCha20-Poly1305 IETF AEAD (the default). Tampering is detected on decrypt,
  and the caller's context is authenticated so a value can't be replayed into a
  different row, column, or tenant. Optionally reads legacy
  `sodium_crypto_secretbox` data during a migration.
- **`LegacySecretboxEncryptionStrategy`** — read/write `sodium_crypto_secretbox`
  (XSalsa20-Poly1305) for backward compatibility with an older secretbox corpus.

## Requirements

- PHP >= 8.2
- `ext-sodium` (bundled with PHP 7.2+)
- `phpnomad/encryption` (the contracts)

## Install

```bash
composer require phpnomad/encryption phpnomad/sodium-integration
```

## Usage

Wire `SodiumEncryptionStrategy` as your `EncryptionStrategy`. Everything else —
the key providers, the `EncryptedValue` model — comes from `phpnomad/encryption`
and is cipher-agnostic. How you persist the sealed value is your call; the
contract imposes no format.

```php
use PHPNomad\Encryption\Providers\ArrayKeyProvider;
use PHPNomad\Encryption\Models\EncryptedValue;
use PHPNomad\Sodium\EncryptionIntegration\Strategies\SodiumEncryptionStrategy;

// A key ring holding one 32-byte key at version 1.
$keys = new ArrayKeyProvider([1 => sodium_crypto_aead_xchacha20poly1305_ietf_keygen()]);

$encryption = new SodiumEncryptionStrategy($keys);

$sealed = $encryption->encrypt('sk-live-super-secret', 'tenant:42:column:token');

// Persist $sealed however you like — e.g. across columns:
$ciphertext = base64_encode($sealed->getCiphertext());
$nonce      = base64_encode($sealed->getNonce());
$version    = $sealed->getKeyVersion();

// Later — rebuild and decrypt with the same context:
$restored  = new EncryptedValue(base64_decode($ciphertext), base64_decode($nonce), $version, SodiumEncryptionStrategy::CIPHER);
$plaintext = $encryption->decrypt($restored, 'tenant:42:column:token');
// => "sk-live-super-secret"
```

### Reading legacy `secretbox` data

If you're adopting this over data previously encrypted with
`sodium_crypto_secretbox`, enable the fallback so unmarked values are tried as
AEAD first and then as secretbox:

```php
$encryption = new SodiumEncryptionStrategy($keys, allowLegacySecretboxFallback: true);
```

New writes are always AEAD; old secretbox values keep decrypting until you
re-encrypt them. `LegacySecretboxEncryptionStrategy` is also provided for
read-only or explicit secretbox handling.

## Security notes

- **XChaCha20-Poly1305** is used because its 24-byte nonce is large enough to
  pick at random per message without collision worries — no nonce counter to
  persist. Keys are 32 bytes.
- Keys are wiped from memory with `sodium_memzero` after each operation.
- Decryption failure (wrong key, wrong context, or tampering) always raises
  `DecryptionFailedException` — never a partial or forged plaintext.
- Associated data is authenticated, **not** encrypted. Don't put secrets in the
  context.

## Testing

```bash
composer install
composer test
```

## License

MIT © Novatorius / Alex Standiford
