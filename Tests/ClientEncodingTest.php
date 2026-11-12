<?php

/**
 * @copyright  Copyright (C) 2005 - 2026 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth1\Tests;

use Joomla\OAuth1\Tests\Stub\TestClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests the percent-encoding and the nonce of \Joomla\OAuth1\Client.
 */
class ClientEncodingTest extends TestCase
{
    /**
     * Provides values and their encoding (RFC 5849, section 3.6).
     *
     * @return  array
     */
    public static function safeEncodeProvider(): array
    {
        return [
            'unreserved characters' => ['AZaz09-._~', 'AZaz09-._~'],
            'plus and space'        => ['a+b c', 'a%2Bb%20c'],
            'reserved characters'   => ['!*\'();:@&=$,/?#[]', '%21%2A%27%28%29%3B%3A%40%26%3D%24%2C%2F%3F%23%5B%5D'],
            'percent'               => ['100%', '100%25'],
            'UTF-8'                 => ['ä', '%C3%A4'],
            'integer'               => [42, '42'],
            'null'                  => [null, ''],
            'array'                 => [['a b', '~'], ['a%20b', '~']],
        ];
    }

    /**
     * Tests the safeEncode method.
     *
     * @param   mixed  $value     The value to encode
     * @param   mixed  $expected  The expected encoding
     */
    #[DataProvider('safeEncodeProvider')]
    public function testSafeEncode($value, $expected)
    {
        $client = (new \ReflectionClass(TestClient::class))->newInstanceWithoutConstructor();

        $this->assertSame($expected, $client->safeEncode($value));
    }

    /**
     * The nonce is a random 128-bit hex string.
     */
    public function testGenerateNonce()
    {
        $nonce = TestClient::generateNonce();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $nonce);
        $this->assertNotSame($nonce, TestClient::generateNonce());
    }
}
