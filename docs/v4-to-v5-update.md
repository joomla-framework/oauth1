## Updating from v4 to v5

The following changes were made to the OAuth1 package between v4 and v5.

### Native parameter, return and property types

`Joomla\OAuth1\Client` now declares native types instead of documenting them in doc blocks only. Subclasses that override one of these methods or redeclare one of these properties must use compatible types, otherwise PHP raises a fatal error when the class is loaded. Callers passing a value of the wrong type now get a `TypeError` instead of a later failure.

| Member | v4 | v5 |
|---|---|---|
| `__construct()` | `$options = [], $version = '1.0a'` | `array\|\ArrayAccess $options = [], string $version = '1.0a'` |
| `oauthRequest()` | `oauthRequest($url, $method, $parameters, $data = [], $headers = [])` | `oauthRequest(string $url, string $method, array $parameters, mixed $data = [], array $headers = []): Response` |
| `toUrl()` | `toUrl($url, $parameters)` | `toUrl(string $url, array\|string $parameters): string` |
| `getOption()` | `getOption($key, $default = null)` | `getOption(string $key, mixed $default = null): mixed` |
| `setOption()` | `setOption($key, $value)` | `setOption(string $key, mixed $value): static` |
| `getToken()` | `getToken()` | `getToken(): array` |
| `setToken()` | `setToken($token)` | `setToken(array $token): static` |
| `$options` | `protected $options` | `protected array\|\ArrayAccess $options` |
| `$token` | `protected $token = []` | `protected array $token = []` |
| `$client` | `protected $client` | `protected Http $client` |
| `$input` | `protected $input` | `protected Input $input` |
| `$application` | `protected $application` | `protected SessionAwareWebApplicationInterface $application` |
| `$version` | `protected $version` | `protected string $version` |

The abstract methods `verifyCredentials()` and `validateResponse()` are unchanged, so existing implementations keep working.

For example, a client that sets a default token in its constructor must keep it an array:

```php
use Joomla\OAuth1\Client;

class MyClient extends Client
{
    protected array $token = [];

    // ...
}
```
