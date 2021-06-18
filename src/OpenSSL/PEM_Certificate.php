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

namespace Comely\Security\OpenSSL;

use Comely\Buffer\AbstractByteArray;

/**
 * Class PEM_Certificate
 * @package Comely\Security\OpenSSL
 */
class PEM_Certificate
{
    /** @var string */
    private string $cert;

    /**
     * @param string|AbstractByteArray $data
     * @param string $type
     * @param string $eolChar
     * @return static
     */
    public static function fromDER(string|AbstractByteArray $data, string $type = "PRIVATE KEY", string $eolChar = "\n"): self
    {
        if ($data instanceof AbstractByteArray) {
            $data = $data->toBase64();
        }

        $type = strtoupper($type);
        $pem = sprintf("-----BEGIN %s-----", $type) . $eolChar;
        $pem .= chunk_split($data, 64, $eolChar);
        $pem .= sprintf("-----END %s-----", $type);

        return new self($pem);
    }

    /**
     * PEM_Certificate constructor.
     * @param string $cert
     */
    public function __construct(string $cert)
    {
        $cert = preg_replace("/(\n|\r\n)/", "\n", $cert);
        if (!$cert || !preg_match('/^[-]{5}[\w\s]+[-]{5}\n[a-z0-9+\/=\n]+[-]{5}[\w\s]+[-]{5}[\n]?$/i', $cert)) {
            throw new \InvalidArgumentException('Invalid PEM format certificate');
        }

        $this->cert = $cert;
    }

    /**
     * @return string
     */
    public function getPEM(): string
    {
        return $this->cert;
    }

    /**
     * @param string $eolChar
     * @return string
     */
    public function getDER(string $eolChar = "\n"): string
    {
        $split = preg_split('/[-]{5}[\w\s]+[-]{5}/i', $this->cert);
        return implode("", explode($eolChar, trim($split[1])));
    }
}
