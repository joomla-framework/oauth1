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
use PHPUnit\Framework\TestCase;

/**
 * Tests DELETE requests sent by \Joomla\OAuth1\Client.
 */
class ClientDeleteRequestTest extends TestCase
{
    /**
     * The data of a DELETE request is signed and must therefore be sent.
     */
    public function testDeleteRequestSendsData()
    {
        $http = $this->createMock(Http::class);

        $http->expects($this->once())
            ->method('delete')
            ->with('https://example.com/item', $this->arrayHasKey('Authorization'), null, ['id' => '5'])
            ->willReturn(new Response('data://text/plain,', 200));

        $client = new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $http,
            new Input([]),
            ['consumer_key' => 'key', 'consumer_secret' => 'secret']
        );

        $client->oauthRequest('https://example.com/item', 'DELETE', [], ['id' => '5']);
    }
}
