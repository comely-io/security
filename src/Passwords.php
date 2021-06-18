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

/**
 * Class Passwords
 * @package Comely\Security
 */
class Passwords
{
    /**
     * Generates a random password from ASCII table indexes 33 to 126
     * @param int $length
     * @param int|null $minimumScore
     * @return string
     */
    public static function Random(int $length = 12, ?int $minimumScore = 4): string
    {
        if ($length < 0) {
            throw new \LengthException('Invalid password length');
        }

        $password = "";
        while (strlen($password) < $length) {
            $password .= chr(mt_rand(33, 126));
        }

        if (is_int($minimumScore) && $minimumScore > self::Strength($password)) {
            return self::Random($length, $minimumScore); // Retry
        }

        return $password;
    }

    /**
     * @param string $password
     * @return int
     */
    public static function Strength(string $password): int
    {
        $score = 0;
        $passwordLength = strlen($password);

        // Lowercase alphabets... +1
        if (preg_match('/[a-z]/', $password)) $score++;
        // Uppercase alphabets... +1
        if (preg_match('/[A-Z]/', $password)) $score++;
        // Numerals... +1
        if (preg_match('/[0-9]/', $password)) $score++;
        // Special characters... +1
        if (preg_match('/[^a-zA-Z0-9]/', $password)) $score++;

        // Length over or equals 12 ... +1
        if ($passwordLength >= 12) $score++;
        // Length over or equals 12 ... +1
        if ($passwordLength >= 16) $score++;

        return $score;
    }
}
