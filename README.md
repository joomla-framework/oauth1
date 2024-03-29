## The OAuth1 Package [![Build Status](https://ci.joomla.org/api/badges/joomla-framework/oauth1/status.svg?ref=refs/heads/2.0-dev)](https://ci.joomla.org/joomla-framework/oauth1)

[![Latest Stable Version](https://poser.pugx.org/joomla/oauth1/v/stable)](https://packagist.org/packages/joomla/oauth1)
[![Total Downloads](https://poser.pugx.org/joomla/oauth1/downloads)](https://packagist.org/packages/joomla/oauth1)
[![Latest Unstable Version](https://poser.pugx.org/joomla/oauth1/v/unstable)](https://packagist.org/packages/joomla/oauth1)
[![License](https://poser.pugx.org/joomla/oauth1/license)](https://packagist.org/packages/joomla/oauth1)

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

See the Twitter and LinkedIn packages for examples demonstrating more about the OAuth1 package.

TODO: add links to the Twitter and LinkedIn packages after this packages are merged.

### More Information
The following resources contain more information:
* [http://api.joomla.org/](Joomla! API Reference)
* [http://tools.ietf.org/html/rfc5849](OAuth RFC)


## Installation via Composer

Add `"joomla/oauth1": "~2.0"` to the require block in your composer.json and then run `composer install`.

```json
{
	"require": {
		"joomla/oauth1": "~2.0"
	}
}
```

Alternatively, you can simply run the following from the command line:

```sh
composer require joomla/oauth1 "~2.0"
```
