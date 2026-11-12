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
 * Tests the request method handling of \Joomla\OAuth1\Client::oauthRequest().
 */
class ClientRequestMethodTest extends TestCase
{
    /**
     * Provides request methods and the Http method that has to send them.
     *
     * @return  array
     */
    public static function requestMethodProvider(): array
    {
        return [
            'get'    => ['get', 'get'],
            'post'   => ['post', 'post'],
            'put'    => ['put', 'put'],
            'delete' => ['delete', 'delete'],
            'patch'  => ['patch', 'patch'],
            'PATCH'  => ['PATCH', 'patch'],
            'Get'    => ['Get', 'get'],
        ];
    }

    /**
     * Request methods are case-insensitive and PATCH is supported.
     *
     * @param   string  $method      The request method passed to oauthRequest()
     * @param   string  $httpMethod  The Http method expected to send the request
     */
    #[DataProvider('requestMethodProvider')]
    public function testRequestMethodIsSent(string $method, string $httpMethod)
    {
        $response = new Response('data://text/plain,', 200);
        $http     = $this->createMock(Http::class);

        $http->expects($this->once())
            ->method($httpMethod)
            ->willReturn($response);

        $client = new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $http,
            new Input([]),
            ['consumer_key' => 'key', 'consumer_secret' => 'secret']
        );

        $this->assertSame($response, $client->oauthRequest('https://example.com/endpoint', $method, []));
    }

    /**
     * An unsupported request method is rejected.
     */
    public function testInvalidRequestMethodThrows()
    {
        $client = new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $this->createStub(Http::class),
            new Input([]),
            ['consumer_key' => 'key', 'consumer_secret' => 'secret']
        );

        $this->expectException(\DomainException::class);

        $client->oauthRequest('https://example.com/endpoint', 'HEAD', []);
    }
}
