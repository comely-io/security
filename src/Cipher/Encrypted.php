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

namespace Comely\Security\Cipher;

use Comely\Security\Exception\CipherException;

/**
 * Class Encrypted
 * @package Comely\Security\Cipher
 */
class Encrypted
{
    /** @var string */
    private string $type;
    /** @var mixed */
    private mixed $data;

    /**
     * Encrypted constructor.
     * @param $data
     * @throws CipherException
     */
    public function __construct($data)
    {
        $this->type = gettype($data);
        $this->data = match ($this->type) {
            "integer", "double", "string" => $data,
            "array", "object" => base64_encode(serialize($data)),
            default => throw new CipherException(sprintf('Cannot encrypt data of type "%s"', $this->type)),
        };
    }

    /**
     * @return array
     */
    public function __serialize(): array
    {
        return [
            "type" => $this->type,
            "data" => $this->data
        ];
    }

    /**
     * @param array $data
     */
    public function __unserialize(array $data): void
    {
        $this->type = $data["type"];
        $this->data = $data["data"];
    }

    /**
     * @return mixed
     * @throws CipherException
     */
    public function stored(): mixed
    {
        switch ($this->type) {
            case "integer":
            case "double":
            case "string":
                return $this->data;
            case "array":
            case "object":
                $obj = unserialize(base64_decode($this->data));
                if ($obj === false || gettype($obj) !== $this->type) {
                    throw new CipherException(
                        sprintf('Failed to unserialize encrypted data of type "%s"', $this->type)
                    );
                }
                return $obj;
        }

        throw new CipherException('Invalid encrypted data type');
    }
}
