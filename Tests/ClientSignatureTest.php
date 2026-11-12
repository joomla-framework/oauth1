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
use Joomla\Test\TestHelper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests the request signing and the Authorization header of \Joomla\OAuth1\Client.
 */
class ClientSignatureTest extends TestCase
{
    /**
     * The OAuth parameters of the reference request from the OAuth Core 1.0 specification, appendix A.5.
     *
     * @var  array
     */
    private const REFERENCE_PARAMETERS = [
        'file'                   => 'vacation.jpg',
        'size'                   => 'original',
        'oauth_consumer_key'     => 'dpf43f3p2l4k3l03',
        'oauth_token'            => 'nnch734d00sl2jdk',
        'oauth_nonce'            => 'kllo9940pd9333jh',
        'oauth_timestamp'        => '1191242096',
        'oauth_version'          => '1.0',
    ];

    /**
     * Creates a client with the consumer and token secrets of the reference request.
     *
     * @param   Http   $http     The HTTP client
     * @param   array  $options  Additional client options
     *
     * @return  TestClient
     */
    private function createClient(Http $http, array $options = []): TestClient
    {
        $client = new TestClient(
            $this->createStub(SessionAwareWebApplicationInterface::class),
            $http,
            new Input([]),
            $options + ['consumer_key' => 'dpf43f3p2l4k3l03', 'consumer_secret' => 'kd94hf93k423kf44']
        );

        return $client->setToken(['key' => 'nnch734d00sl2jdk', 'secret' => 'pfkkdhi9sl3r4s00']);
    }

    /**
     * Sends a POST request through the client and returns the Authorization header that was sent.
     *
     * @param   array  $parameters  The OAuth parameters
     * @param   array  $options     Additional client options
     *
     * @return  string
     */
    private function sendAndCaptureHeader(array $parameters, array $options = []): string
    {
        $sentHeaders = [];
        $http        = $this->createMock(Http::class);

        $http->expects($this->once())
            ->method('post')
            ->willReturnCallback(
                function ($url, $data, array $headers) use (&$sentHeaders) {
                    $sentHeaders = $headers;

                    return new Response('data://text/plain,', 200);
                }
            );

        $this->createClient($http, $options)->oauthRequest('https://example.com/endpoint', 'POST', $parameters);

        return $sentHeaders['Authorization'];
    }

    /**
     * Every key and value in the Authorization header must be percent-encoded, not only the first one.
     */
    public function testAuthorizationHeaderEncodesEveryParameter()
    {
        $header = $this->sendAndCaptureHeader(['oauth_token' => 'a b', 'oauth_verifier' => 'x"y=z']);

        $this->assertStringContainsString('oauth_token="a%20b"', $header);
        $this->assertStringContainsString('oauth_verifier="x%22y%3Dz"', $header);
        $this->assertMatchesRegularExpression(
            '/^OAuth [A-Za-z0-9%._~-]+="[A-Za-z0-9%._~-]*"(, [A-Za-z0-9%._~-]+="[A-Za-z0-9%._~-]*")*$/',
            $header
        );
    }

    /**
     * The signature must be percent-encoded exactly once in the Authorization header.
     */
    public function testSignatureMatchesReferenceVectorAndIsEncodedOnce()
    {
        $client     = $this->createClient($this->createStub(Http::class));
        $parameters = TestHelper::invoke(
            $client,
            'signRequest',
            'http://photos.example.net/photos',
            'GET',
            self::REFERENCE_PARAMETERS + ['oauth_signature_method' => 'HMAC-SHA1']
        );

        $this->assertSame('tR3+Ty81lMeYAr/Fid0kMTYa/WM=', $parameters['oauth_signature']);
        $this->assertStringContainsString(
            'oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"',
            TestHelper::invoke($client, 'createHeader', $parameters)
        );
    }

    /**
     * Provides the supported signature methods and the expected signature of the reference request.
     *
     * @return  array
     */
    public static function signatureMethodProvider(): array
    {
        return [
            'HMAC-SHA1'   => ['HMAC-SHA1', 'tR3+Ty81lMeYAr/Fid0kMTYa/WM='],
            'HMAC-SHA256' => ['HMAC-SHA256', 'WVPzl1j6ZsnkIjWr7e3OZ3jkenL57KwaLFhYsroX1hg='],
            'PLAINTEXT'   => ['PLAINTEXT', 'kd94hf93k423kf44&pfkkdhi9sl3r4s00'],
        ];
    }

    /**
     * Tests the supported signature methods.
     *
     * @param   string  $signatureMethod  The signature method
     * @param   string  $expected         The expected signature
     */
    #[DataProvider('signatureMethodProvider')]
    public function testSignatureMethods(string $signatureMethod, string $expected)
    {
        $parameters = TestHelper::invoke(
            $this->createClient($this->createStub(Http::class)),
            'signRequest',
            'http://photos.example.net/photos',
            'GET',
            self::REFERENCE_PARAMETERS + ['oauth_signature_method' => $signatureMethod]
        );

        $this->assertSame($expected, $parameters['oauth_signature']);
    }

    /**
     * The signature_method option selects the signature method of a request.
     */
    public function testSignatureMethodOption()
    {
        $this->assertStringContainsString(
            'oauth_signature_method="HMAC-SHA1"',
            $this->sendAndCaptureHeader([])
        );

        $header = $this->sendAndCaptureHeader([], ['signature_method' => 'PLAINTEXT']);

        $this->assertStringContainsString('oauth_signature_method="PLAINTEXT"', $header);
        $this->assertStringContainsString('oauth_signature="kd94hf93k423kf44%26pfkkdhi9sl3r4s00"', $header);
    }

    /**
     * An unsupported signature method is rejected.
     */
    public function testUnsupportedSignatureMethodThrows()
    {
        $http = $this->createMock(Http::class);
        $http->expects($this->never())->method('post');

        $this->expectException(\DomainException::class);

        $this->createClient($http, ['signature_method' => 'RSA-SHA1'])
            ->oauthRequest('https://example.com/endpoint', 'POST', []);
    }
}
