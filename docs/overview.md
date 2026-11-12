# OAuth1 package

### Using the OAuth1 Package

The OAuth1 package supports OAuth 1.0 and 1.0a protocol versions. The client facilitates authorised RESTful HTTP requests. You can find the OAuth RFC at [http://tools.ietf.org/html/rfc5849](http://tools.ietf.org/html/rfc5849).

The Client is abstract, it must be extended and have the two abstract methods implemented. These methods are verifyCredentials and validateResponse:
* verifyCredentials is used to check if an existing access token is still valid. Servers may have different ways of testing the access token validity, for example Twitter has a specific URL for this. There are several reasons an access token may be invalid: the token expires after some time, the user changes his password which invalidates the access token, the user de-authorizes your app, the user logs out.
* validateResponse method is used to check the response codes. This method abstract because servers may have different response error bodies.

By default the client will act as an OAuth 1.0a client. If you need an OAuth 1.0 client, than you have to set the constructor $version parameter to '1.0'. The client requires additional options and this can be done by injecting in a Registry object:

```php
use Joomla\Oauth1\Client;
use Joomla\Registry\Registry;

$options = new Registry;
$options->set('consumer_key', $key);
$options->set('consumer_secret', $secret);
$options->set('callback', $my_url);
$options->set('accessTokenURL', $accessToken);
$options->set('authenticateURL', $authenticate);
$options->set('authoriseURL', $authorise);
$options->set('requestTokenURL', $requestToken);

// Call the Client constructor.
parent::__construct($this->options);
```

By default you have to set and send headers manually in your application, but if you want this to be done automatically by the client you can set Registry option 'sendheaders' to true.

```php
$options->set('sendheaders', true);
```

Now you can authenticate the user and request him to authorise your application in order to get an access token, but if you already have an access token stored you can set it and if it's still valid your application will use it.

```php
// Set the stored access token.
$oauth->setToken($token);

$access_token = $oauth->authenticate();
```

When calling the authenticate() method, your stored access token will be used only if it's valid, a new one will be created if you don't have an access token or if the stored one is not valid. The method will return a valid access token that's going to be used.

Now you can perform authorised requests using the oauthRequest method.

### A More Complete Example

The Twitter and LinkedIn packages were once planned as the reference consumers of this package, but
neither was ever merged into the Framework, so there is no worked example to point at. The
subclass sketch above is the complete picture: implement `verifyCredentials()` and
`validateResponse()` against your provider's API and drive the rest through `authenticate()` and
`oauthRequest()`.

### More Information
The following resources contain more information:
* [Joomla! API Reference](https://api.joomla.org/)
* [OAuth 1.0a — RFC 5849](https://tools.ietf.org/html/rfc5849)



## Things to know before you build on this

**The class is abstract and ships without an implementation.** You must subclass it and implement
`verifyCredentials()` and `validateResponse()`; there is no ready-made provider in the package.

**Only lower-case-safe HTTP methods work.** `oauthRequest()` validates the method with
`strtoupper()` but then dispatches on the raw value, so `oauthRequest($url, 'get', …)` passes
validation, matches no branch and leaves `$response` undefined. Always pass upper-case. `PATCH`
is accepted by the validation but has no branch at all, so it cannot be used.

**Only the first Authorization parameter is encoded.** `createHeader()` percent-encodes the value
of the first parameter and inserts every following one raw. Since `oauth_verifier` comes straight
from the callback query string, a value containing a quote or a newline lands unencoded in the
`Authorization` header. Validate the verifier before calling `authenticate()` if the provider's
values can contain anything unusual.

**The signature base string is not normalised.** RFC 5849 requires the URL to be split from its
query string, with those parameters folded into the signed parameter list. This implementation
signs the URL as given, so any request to a URL that already carries a query string produces a
signature the provider cannot reproduce. Pass query parameters through the `$data` argument
instead of embedding them in the URL.

**HMAC-SHA1 is the only signature method.** There is no RSA-SHA1 and no HMAC-SHA256, and no
extension point to add one.

**The request token check is not constant time.** `authenticate()` compares the session token to
the returned `oauth_token` with `strcmp()`, and reads the request value through the default `cmd`
filter, which strips characters some providers use. If your provider's tokens contain anything
outside `[A-Za-z0-9_.-]`, read the value with the `raw` filter and compare with `hash_equals()`.

**Access tokens are not persisted.** The request token is written to the session, the access token
is not. Store it yourself after `authenticate()` returns, or it is gone at the end of the request.
