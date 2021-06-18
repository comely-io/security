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

use Comely\Security\Exception\PRNG_Exception;

/**
 * Class PRNG
 * @package Comely\Security
 */
class PRNG
{
    /**
     * @param int $len
     * @return string
     * @throws PRNG_Exception
     */
    public static function randomBytes(int $len): string
    {
        try {
            return random_bytes($len);
        } catch (\Exception) {
            throw new PRNG_Exception('Failed to generate PRNG entropy');
        }
    }
}

