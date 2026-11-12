<?php

/**
 * @copyright  Copyright (C) 2005 - 2026 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth1\Tests;

use Joomla\Application\SessionAwareWebApplicationInterface;
use Joomla\Http\Http;
use Joomla\Input\Input;
use Joomla\OAuth1\Tests\Stub\TestClient;
use Joomla\Test\TestHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests the signature base string of \Joomla\OAuth1\Client against RFC 5849.
 */
class ClientBaseStringTest extends TestCase
{
    /**
     * Creates the signature base string through the client.
     *
     * @param   string  $url         The request URL
     * @param   string  $method      The request method
     * @param   array   $parameters  The request parameters
     *
     * @return  string
     */
    private function baseString(string $url, string $method, array $parameters): string
    {
        $client = new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $this->createStub(Http::class),
            new Input([]),
            []
        );

        return TestHelper::invoke($client, 'baseString', $url, $method, $parameters);
    }

    /**
     * The example of RFC 5849, section 3.4.1.1: query parameters are part of the parameter list, not of the base URI,
     * and pairs with the same name are sorted by value.
     */
    public function testRfc5849BaseStringExample()
    {
        $this->assertSame(
            'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26'
            . 'c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26'
            . 'oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7',
            $this->baseString(
                'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b',
                'POST',
                [
                    'oauth_consumer_key'     => '9djdj82h48djs9d2',
                    'oauth_token'            => 'kkk9d7dh3k39sjv7',
                    'oauth_signature_method' => 'HMAC-SHA1',
                    'oauth_timestamp'        => '137131201',
                    'oauth_nonce'            => '7d8f3e4a',
                    'c2'                     => '',
                    'a3'                     => '2 q',
                ]
            )
        );
    }

    /**
     * The example of RFC 5849, section 1.2: a GET request with a query string yields the documented signature.
     */
    public function testRfc5849SignatureExample()
    {
        $base = $this->baseString(
            'http://photos.example.net/photos?file=vacation.jpg&size=original',
            'GET',
            [
                'oauth_consumer_key'     => 'dpf43f3p2l4k3l03',
                'oauth_token'            => 'nnch734d00sl2jdk',
                'oauth_signature_method' => 'HMAC-SHA1',
                'oauth_timestamp'        => '137131202',
                'oauth_nonce'            => 'chapoH',
            ]
        );

        $this->assertSame(
            'MdpQcU8iPSUjWoN/UDMsK2sui9I=',
            base64_encode(hash_hmac('sha1', $base, 'kd94hf93k423kf44&pfkkdhi9sl3r4s00', true))
        );
    }

    /**
     * Provides URLs and their base string URI (RFC 5849, section 3.4.1.2).
     *
     * @return  array
     */
    public static function baseUriProvider(): array
    {
        return [
            'upper-case scheme and host, default port' => ['HTTP://EXAMPLE.COM:80/r%20v/X?id=123', 'http://example.com/r%20v/X'],
            'non-default port, query'                  => ['https://www.example.net:8080/?q=1', 'https://www.example.net:8080/'],
            'default HTTPS port'                       => ['https://example.com:443/path', 'https://example.com/path'],
            'empty path, fragment'                     => ['https://example.com#fragment', 'https://example.com/'],
        ];
    }

    /**
     * Tests the normalisation of the base string URI.
     *
     * @param   string  $url       The request URL
     * @param   string  $expected  The expected base string URI
     */
    #[DataProvider('baseUriProvider')]
    public function testBaseStringUriIsNormalised(string $url, string $expected)
    {
        $this->assertSame(
            'GET&' . rawurlencode($expected) . '&',
            preg_replace('/&[^&]*$/', '&', $this->baseString($url, 'GET', []))
        );
    }

    /**
     * Array values are expanded into one pair per value and sorted by value (RFC 5849, section 3.4.1.3.2).
     */
    public function testArrayValuesAreSorted()
    {
        $this->assertSame(
            'GET&https%3A%2F%2Fexample.com%2F&a%3D1%26a%3D2%26b%3D3',
            $this->baseString('https://example.com/', 'GET', ['b' => '3', 'a' => ['2', '1']])
        );
    }

    /**
     * The request method is upper-cased in the base string.
     */
    public function testMethodIsUpperCased()
    {
        $this->assertStringStartsWith('POST&', $this->baseString('https://example.com/', 'post', []));
    }
}
