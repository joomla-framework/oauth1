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
 * Tests the authorisation URL of \Joomla\OAuth1\Client.
 */
class ClientAuthorisationUrlTest extends TestCase
{
    /**
     * Creates a client holding a request token.
     *
     * @param   SessionAwareWebApplicationInterface  $application  The application
     * @param   array                                $options      The client options
     * @param   string                               $token        The request token
     *
     * @return  TestClient
     */
    private function createClient(SessionAwareWebApplicationInterface $application, array $options, string $token): TestClient
    {
        $client = new TestClient($application, $this->createStub(Http::class), new Input([]), $options);

        return $client->setToken(['key' => $token, 'secret' => 'secret']);
    }

    /**
     * Provides options, request tokens and the expected authorisation URL.
     *
     * @return  array
     */
    public static function authorisationUrlProvider(): array
    {
        return [
            'plain'                => [['authoriseURL' => 'https://example.com/authorize'], 'token', 'https://example.com/authorize?oauth_token=token'],
            'token is encoded'     => [['authoriseURL' => 'https://example.com/authorize'], 'a&b#c', 'https://example.com/authorize?oauth_token=a%26b%23c'],
            'existing query'       => [['authoriseURL' => 'https://example.com/authorize?lang=en'], 'token', 'https://example.com/authorize?lang=en&oauth_token=token'],
            'scope as array'       => [
                ['authoriseURL' => 'https://example.com/authorize', 'scope' => ['read', 'write']],
                'token',
                'https://example.com/authorize?oauth_token=token&scope=read%20write',
            ],
            'scope as string'      => [
                ['authoriseURL' => 'https://example.com/authorize', 'scope' => 'read'],
                'token',
                'https://example.com/authorize?oauth_token=token&scope=read',
            ],
        ];
    }

    /**
     * Tests the getAuthorisationUrl method.
     *
     * @param   array   $options   The client options
     * @param   string  $token     The request token
     * @param   string  $expected  The expected URL
     */
    #[DataProvider('authorisationUrlProvider')]
    public function testGetAuthorisationUrl(array $options, string $token, string $expected)
    {
        $this->assertSame(
            $expected,
            $this->createClient($this->createStub(SessionAwareWebApplicationInterface::class), $options, $token)->getAuthorisationUrl()
        );
    }

    /**
     * With the sendheaders option the user is redirected to the authorisation URL.
     */
    public function testAuthoriseRedirectsToAuthorisationUrl()
    {
        $application = $this->createMock(SessionAwareWebApplicationInterface::class);
        $application->expects($this->once())
            ->method('redirect')
            ->with('https://example.com/authorize?lang=en&oauth_token=a%26b');

        TestHelper::invoke(
            $this->createClient(
                $application,
                ['authoriseURL' => 'https://example.com/authorize?lang=en', 'sendheaders' => true],
                'a&b'
            ),
            'authorise'
        );
    }
}
