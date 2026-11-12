<?php

/**
 * @copyright  Copyright (C) 2005 - 2026 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth1\Tests;

use Joomla\Application\SessionAwareWebApplicationInterface;
use Joomla\Http\Http;
use Joomla\Http\Response;
use Joomla\Input\Input;
use Joomla\OAuth1\Tests\Stub\TestClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests the query string of GET requests sent by \Joomla\OAuth1\Client.
 */
class ClientQueryTest extends TestCase
{
    /**
     * Creates a client.
     *
     * @param   Http  $http  The HTTP client
     *
     * @return  TestClient
     */
    private function createClient(Http $http): TestClient
    {
        return new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $http,
            new Input([]),
            ['consumer_key' => 'key', 'consumer_secret' => 'secret']
        );
    }

    /**
     * Provides URLs, parameters and the expected URL.
     *
     * @return  array
     */
    public static function toUrlProvider(): array
    {
        return [
            'existing query is kept'        => ['http://x/y?since=2024', ['q' => 'a&b'], 'http://x/y?since=2024&q=a%26b'],
            'existing query, no parameters' => ['http://x/y?since=2024', [], 'http://x/y?since=2024'],
            'values are encoded'            => ['http://x/y', ['q' => 'a b&c=d', 'r' => '100%'], 'http://x/y?q=a%20b%26c%3Dd&r=100%25'],
            'fragment stays at the end'     => ['http://x/y#top', ['q' => 'a'], 'http://x/y?q=a#top'],
            'trailing question mark'        => ['http://x/y?', ['q' => 'a'], 'http://x/y?q=a'],
        ];
    }

    /**
     * Tests the toUrl method.
     *
     * @param   string  $url         The URL
     * @param   array   $parameters  The parameters to add
     * @param   string  $expected    The expected URL
     */
    #[DataProvider('toUrlProvider')]
    public function testToUrl(string $url, array $parameters, string $expected)
    {
        $this->assertSame($expected, $this->createClient($this->createStub(Http::class))->toUrl($url, $parameters));
    }

    /**
     * A GET request keeps the query of the URL and sends the data encoded.
     */
    public function testGetRequestKeepsQueryAndEncodesData()
    {
        $http = $this->createMock(Http::class);

        $http->expects($this->once())
            ->method('get')
            ->with('http://x/y?since=2024&q=a%26b')
            ->willReturn(new Response('data://text/plain,', 200));

        $this->createClient($http)->oauthRequest('http://x/y?since=2024', 'GET', [], ['q' => 'a&b']);
    }
}
