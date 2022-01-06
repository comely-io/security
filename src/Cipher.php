<?php
/*
 * This file is a part of "comely-io/security" package.
 * https://github.com/comely-io/security
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/comely-io/security/blob/master/LICENSE
 */

declare(strict_types=1);

namespace Comely\Security;

use Comely\Buffer\AbstractByteArray;
use Comely\Buffer\Buffer;
use Comely\Security\Cipher\Encrypted;
use Comely\Security\Exception\CipherException;

/**
 * Class Cipher
 * @package Comely\Security
 */
class Cipher
{
    /** @var string */
    private string $key;
    /** @var string */
    private string $cipher;
    /** @var int */
    private int $ivLength;

    /**
     * Cipher constructor.
     * @param string|AbstractByteArray $key
     * @param string $cipher
     * @throws CipherException
     */
    public function __construct(string|AbstractByteArray $key, string $cipher = "aes-256-cbc")
    {
        if (!in_array($cipher, openssl_get_cipher_methods())) {
            throw new CipherException('Invalid or unavailable cipher method');
        }

        $this->cipher = $cipher;
        $this->key = $key instanceof AbstractByteArray ? $key->raw() : $key;

        // Check key length
        preg_match('/-[0-9]+-/', $cipher, $matches);
        if (!$matches) {
            throw new CipherException(sprintf('Unsupported cipher "%s"', $this->cipher));
        }

        $reqLen = intval(trim($matches[0], "-")) / 8;
        if (strlen($this->key) !== $reqLen) {
            throw new CipherException(
                sprintf('Expected key of %d bytes for cipher %s; got %d bytes', $reqLen, $this->cipher, strlen($this->key))
            );
        }

        $this->ivLength = openssl_cipher_iv_length($cipher);
    }

    /**
     * @return array
     */
    public function __debugInfo(): array
    {
        return [
            "cipher" => $this->cipher,
            "key" => sprintf("%d-bit secret key", strlen($this->key) * 8),
        ];
    }

    /**
     * Creates a new Cipher instance using a remixed key with deterministic phrase/key in argument
     * @param string $key
     * @param int $iterations
     * @return $this
     * @throws CipherException
     */
    public function remixChild(string $key, int $iterations = 1): static
    {
        $algo = match (strlen($this->key)) {
            32 => "sha256",
            16 => "sha1",
            default => throw new CipherException('Cannot remix a %d-bit secret key cipher', strlen($this->key) * 8)
        };

        return new self($this->pbkdf2($algo, $key, $iterations));
    }

    /**
     * @param int|float|string|object|array $item
     * @param bool $zeroPadding
     * @return Buffer
     * @throws CipherException
     */
    public function encrypt(int|float|string|object|array $item, bool $zeroPadding = false): Buffer
    {
        $options = OPENSSL_RAW_DATA;
        if ($zeroPadding) {
            $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        }

        $iv = PRNG::randomBytes($this->ivLength);
        $encrypted = openssl_encrypt(serialize(new Encrypted($item)), $this->cipher, $this->key, $options, $iv);
        if (!$encrypted) {
            throw new CipherException('Encryption op failed; using OpenSSL');
        }

        return (new Buffer($iv . $encrypted))->readOnly();
    }

    /**
     * @param string|AbstractByteArray $encrypted
     * @param bool $zeroPadding
     * @return mixed
     * @throws CipherException
     */
    public function decrypt(string|AbstractByteArray $encrypted, bool $zeroPadding = false): mixed
    {
        $options = OPENSSL_RAW_DATA;
        if ($zeroPadding) {
            $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        }

        $encrypted = $encrypted instanceof AbstractByteArray ? $encrypted->raw() : $encrypted;
        $iv = substr($encrypted, 0, $this->ivLength);
        $data = substr($encrypted, $this->ivLength);
        if (!$iv || !$data) {
            throw new CipherException('Incomplete encrypted bytes');
        }

        $decrypted = openssl_decrypt($data, $this->cipher, $this->key, $options, $iv);
        if (!$decrypted) {
            throw new CipherException('Decryption op failed; using OpenSSL');
        }

        $object = unserialize($decrypted);
        if (!$object instanceof Encrypted) {
            throw new CipherException('Unserialize encrypted object failed');
        }

        return $object->stored();
    }

    /**
     * @param string $algo
     * @param string $data
     * @return Buffer
     * @throws CipherException
     */
    public function hmac(string $algo, string $data): Buffer
    {
        if (!in_array($algo, hash_hmac_algos())) {
            throw new CipherException('Hash HMAC algorithm not available');
        }

        $hmac = hash_hmac($algo, $data, $this->key, true);
        if (!$hmac) {
            throw new CipherException('Failed to compute HMAC');
        }

        return (new Buffer($hmac))->readOnly();
    }

    /**
     * @param string $algo
     * @param string $data
     * @param int $iterations
     * @return Buffer
     * @throws CipherException
     */
    public function pbkdf2(string $algo, string $data, int $iterations): Buffer
    {
        if (!in_array($algo, hash_algos())) {
            throw new CipherException('Hash PBKDF2 algorithm not available');
        }

        $digest = hash_pbkdf2($algo, $data, $this->key, $iterations, 0, true);
        if (!$digest) {
            throw new CipherException('Failed to compute PBKDF2');
        }

        return new Buffer($digest);
    }
}

