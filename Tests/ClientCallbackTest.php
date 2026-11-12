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
use Joomla\Session\SessionInterface;
use Joomla\Test\TestHelper;
use PHPUnit\Framework\TestCase;

/**
 * Tests the request token handling of \Joomla\OAuth1\Client on the provider's callback.
 */
class ClientCallbackTest extends TestCase
{
    /**
     * Creates a client.
     *
     * @param   Http              $http     The HTTP client
     * @param   SessionInterface  $session  The session
     * @param   array             $input    The request data
     * @param   array             $options  Additional client options
     *
     * @return  TestClient
     */
    private function createClient(Http $http, SessionInterface $session, array $input, array $options = []): TestClient
    {
        $application = $this->createStub(SessionAwareWebApplicationInterface::class);
        $application->method('getSession')->willReturn($session);

        return new TestClient(
            $application,
            $http,
            new Input($input),
            $options + [
                'consumer_key'    => 'key',
                'consumer_secret' => 'secret',
                'requestTokenURL' => 'https://example.com/request_token',
                'accessTokenURL'  => 'https://example.com/access_token',
            ]
        );
    }

    /**
     * Creates an HTTP client that answers every POST request with the given body.
     *
     * @param   string  $body  The response body
     *
     * @return  Http
     */
    private function createHttp(string $body): Http
    {
        $http = $this->createStub(Http::class);
        $http->method('post')->willReturn(new Response('data://text/plain,' . $body, 200));

        return $http;
    }

    /**
     * A callback must not be accepted when the session holds no request token, even if the callback carries no
     * oauth_token either.
     */
    public function testCallbackWithoutStoredRequestTokenThrows()
    {
        $http = $this->createMock(Http::class);
        $http->expects($this->never())->method('post');

        $session = $this->createStub(SessionInterface::class);
        $session->method('get')->willReturn(null);

        $this->expectException(\DomainException::class);

        $this->createClient($http, $session, ['oauth_verifier' => 'verifier'])->authenticate();
    }

    /**
     * The returned oauth_token is compared unfiltered, so tokens with characters outside the "cmd" filter work.
     */
    public function testReturnedTokenIsComparedUnfiltered()
    {
        $session = $this->createStub(SessionInterface::class);
        $session->method('get')->willReturnMap([
            ['oauth_token.key', null, 'ab/c+d='],
            ['oauth_token.secret', null, 'secret'],
        ]);

        $client = $this->createClient(
            $this->createHttp('oauth_token=access&oauth_token_secret=access_secret'),
            $session,
            ['oauth_verifier' => 'verifier', 'oauth_token' => 'ab/c+d=']
        );

        $this->assertSame(['key' => 'access', 'secret' => 'access_secret'], $client->authenticate());
    }

    /**
     * A returned oauth_token that differs from the stored request token is rejected.
     */
    public function testMismatchingTokenThrows()
    {
        $session = $this->createStub(SessionInterface::class);
        $session->method('get')->willReturnMap([
            ['oauth_token.key', null, 'stored'],
            ['oauth_token.secret', null, 'secret'],
        ]);

        $this->expectException(\DomainException::class);

        $this->createClient(
            $this->createHttp('oauth_token=access&oauth_token_secret=access_secret'),
            $session,
            ['oauth_verifier' => 'verifier', 'oauth_token' => 'other']
        )->authenticate();
    }

    /**
     * The request token is removed from the session once it has been exchanged.
     */
    public function testRequestTokenIsRemovedAfterExchange()
    {
        $removed = [];
        $session = $this->createMock(SessionInterface::class);
        $session->method('get')->willReturnMap([
            ['oauth_token.key', null, 'token'],
            ['oauth_token.secret', null, 'secret'],
        ]);
        $session->expects($this->exactly(2))
            ->method('remove')
            ->willReturnCallback(
                function (string $name) use (&$removed) {
                    $removed[] = $name;

                    return null;
                }
            );

        $this->createClient(
            $this->createHttp('oauth_token=access&oauth_token_secret=access_secret'),
            $session,
            ['oauth_verifier' => 'verifier', 'oauth_token' => 'token']
        )->authenticate();

        $this->assertSame(['oauth_token.key', 'oauth_token.secret'], $removed);
    }

    /**
     * The session_namespace option keeps the request tokens of several clients apart.
     */
    public function testSessionNamespace()
    {
        $stored  = [];
        $session = $this->createStub(SessionInterface::class);
        $session->method('set')->willReturnCallback(
            function (string $name, $value) use (&$stored) {
                $stored[$name] = $value;

                return null;
            }
        );

        TestHelper::invoke(
            $this->createClient(
                $this->createHttp('oauth_token=token&oauth_token_secret=secret&oauth_callback_confirmed=true'),
                $session,
                [],
                ['session_namespace' => 'provider_a']
            ),
            'generateRequestToken'
        );

        $this->assertSame(['provider_a.key' => 'token', 'provider_a.secret' => 'secret'], $stored);

        $session = $this->createStub(SessionInterface::class);
        $session->method('get')->willReturnMap([
            ['provider_a.key', null, 'token'],
            ['provider_a.secret', null, 'secret'],
        ]);

        $client = $this->createClient(
            $this->createHttp('oauth_token=access&oauth_token_secret=access_secret'),
            $session,
            ['oauth_verifier' => 'verifier', 'oauth_token' => 'token'],
            ['session_namespace' => 'provider_a']
        );

        $this->assertSame(['key' => 'access', 'secret' => 'access_secret'], $client->authenticate());
    }
}
