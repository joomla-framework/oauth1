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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests the handling of token responses in \Joomla\OAuth1\Client.
 */
class ClientTokenResponseTest extends TestCase
{
    /**
     * Creates a client whose HTTP client returns the given body for every POST request.
     *
     * @param   string            $body     The response body
     * @param   SessionInterface  $session  The session
     *
     * @return  TestClient
     */
    private function createClient(string $body, SessionInterface $session): TestClient
    {
        $http = $this->createStub(Http::class);
        $http->method('post')->willReturn(new Response('data://text/plain,' . $body, 200));

        $application = $this->createStub(SessionAwareWebApplicationInterface::class);
        $application->method('getSession')->willReturn($session);

        return new TestClient(
            $application,
            $http,
            new Input([]),
            [
                'consumer_key'    => 'key',
                'consumer_secret' => 'secret',
                'requestTokenURL' => 'https://example.com/request_token',
                'accessTokenURL'  => 'https://example.com/access_token',
            ]
        );
    }

    /**
     * Provides invalid request token responses and the expected part of the exception message.
     *
     * @return  array
     */
    public static function invalidRequestTokenResponseProvider(): array
    {
        return [
            'oauth_problem'          => ['oauth_problem=consumer_key_rejected', 'consumer_key_rejected'],
            'JSON error'             => ['{"error":"invalid consumer"}', '{"error":"invalid consumer"}'],
            'no secret'              => ['oauth_token=token&oauth_callback_confirmed=true', 'oauth_token=token'],
            'no callback confirmed'  => ['oauth_token=token&oauth_token_secret=secret', 'Bad request token!'],
        ];
    }

    /**
     * A request token response without a token throws and stores nothing in the session.
     *
     * @param   string  $body     The response body
     * @param   string  $message  The expected part of the exception message
     */
    #[DataProvider('invalidRequestTokenResponseProvider')]
    public function testInvalidRequestTokenResponseThrows(string $body, string $message)
    {
        $session = $this->createMock(SessionInterface::class);
        $session->expects($this->never())->method('set');

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage($message);

        TestHelper::invoke($this->createClient($body, $session), 'generateRequestToken');
    }

    /**
     * An access token response without a token throws.
     */
    public function testInvalidAccessTokenResponseThrows()
    {
        $client = $this->createClient('oauth_problem=token_rejected', $this->createStub(SessionInterface::class));
        $client->setToken(['key' => 'token', 'secret' => 'secret', 'verifier' => 'verifier']);

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('token_rejected');

        TestHelper::invoke($client, 'generateAccessToken');
    }

    /**
     * A valid access token response is stored as the token.
     */
    public function testValidAccessTokenResponse()
    {
        $client = $this->createClient('oauth_token=access&oauth_token_secret=access_secret', $this->createStub(SessionInterface::class));
        $client->setToken(['key' => 'token', 'secret' => 'secret', 'verifier' => 'verifier']);

        TestHelper::invoke($client, 'generateAccessToken');

        $this->assertSame(['key' => 'access', 'secret' => 'access_secret'], $client->getToken());
    }
}
