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
use PHPUnit\Framework\TestCase;

/**
 * Tests the native types of the public API of \Joomla\OAuth1\Client.
 */
class ClientTypesTest extends TestCase
{
    /**
     * Creates a client.
     *
     * @return  TestClient
     */
    private function createClient(): TestClient
    {
        return new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $this->createStub(Http::class),
            new Input([]),
            []
        );
    }

    /**
     * The setters return the client.
     */
    public function testSettersAreFluent()
    {
        $client = $this->createClient();

        $this->assertSame($client, $client->setOption('consumer_key', 'key'));
        $this->assertSame($client, $client->setToken(['key' => 'key', 'secret' => 'secret']));
        $this->assertSame('key', $client->getOption('consumer_key'));
        $this->assertSame(['key' => 'key', 'secret' => 'secret'], $client->getToken());
    }

    /**
     * A token must be an array.
     */
    public function testSetTokenRequiresArray()
    {
        $this->expectException(\TypeError::class);

        $this->createClient()->setToken('token');
    }

    /**
     * The options must be an array or implement ArrayAccess.
     */
    public function testOptionsRequireArrayOrArrayAccess()
    {
        $this->expectException(\TypeError::class);

        new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $this->createStub(Http::class),
            new Input([]),
            'options'
        );
    }
}
