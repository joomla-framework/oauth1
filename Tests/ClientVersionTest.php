<?php

/**
 * @copyright  Copyright (C) 2005 - 2026 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE
 */

namespace Joomla\OAuth1\Tests;

use Joomla\Application\SessionAwareWebApplicationInterface;
use Joomla\Http\Http;
use Joomla\Input\Input;
use Joomla\OAuth1\Client;
use Joomla\OAuth1\Tests\Stub\TestClient;
use Joomla\Test\TestHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests the protocol version of \Joomla\OAuth1\Client.
 */
class ClientVersionTest extends TestCase
{
    /**
     * Creates a client.
     *
     * @param   mixed  $version  The protocol version
     *
     * @return  TestClient
     */
    private function createClient($version): TestClient
    {
        return new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $this->createStub(Http::class),
            new Input([]),
            [],
            $version
        );
    }

    /**
     * Tests the supported versions.
     */
    public function testSupportedVersions()
    {
        $this->assertSame('1.0a', TestHelper::getValue($this->createClient(Client::VERSION_1_0A), 'version'));
        $this->assertSame('1.0', TestHelper::getValue($this->createClient(Client::VERSION_1_0), 'version'));
    }

    /**
     * Provides unsupported versions.
     *
     * @return  array
     */
    public static function unsupportedVersionProvider(): array
    {
        return [
            'upper-case A' => ['1.0A'],
            'OAuth 2'      => ['2.0'],
            'empty'        => [''],
        ];
    }

    /**
     * An unsupported version is rejected instead of silently selecting the OAuth 1.0 flow.
     *
     * @param   string  $version  The protocol version
     */
    #[DataProvider('unsupportedVersionProvider')]
    public function testUnsupportedVersionThrows(string $version)
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->createClient($version);
    }
}
