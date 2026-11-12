# Updating from v3 to v4

Release 4.0.0 raises the PHP requirement, follows `joomla/http` to PSR-7 responses, and drops the
constructor's options validation.

## At a glance

| | v3 (3.0.0) | v4 (4.0.0) |
|---|---|---|
| PHP | `^8.1.0` | `^8.3.0` |
| Response objects | `Joomla\Http\Response` with public properties | PSR-7 `ResponseInterface` |
| Constructor `$options` check | throws `InvalidArgumentException` | **removed** |
| `getToken()` with no token | `null` | `[]` |

## Minimum supported PHP version raised

All Framework packages now require **PHP 8.3** or newer.

## Responses are PSR-7 objects

`joomla/http` 4.0 returns PSR-7 responses, so the internal parsing changed:

```php
// v3
parse_str($response->body, $params);

// v4
parse_str($response->getBody()->getContents(), $params);
```

This reaches your code through the two abstract methods you implement. `validateResponse()` and
`verifyCredentials()` receive a PSR-7 response now:

```php
// v3
public function validateResponse($url, $response)
{
    if ($response->code != 200) {
        throw new \DomainException($response->body);
    }
}

// v4
public function validateResponse($url, $response)
{
    if ($response->getStatusCode() != 200) {
        throw new \DomainException((string) $response->getBody());
    }
}
```

Prefer `(string) $response->getBody()` over `getBody()->getContents()` — the cast rewinds the
stream, so reading it a second time still returns the body.

## The constructor no longer validates `$options`

```php
// Removed in 4.0.0
if (!\is_array($options) && !($options instanceof \ArrayAccess)) {
    throw new \InvalidArgumentException(
        'The options param must be an array or implement the ArrayAccess interface.'
    );
}
```

A wrong type now surfaces later, at the first `getOption()` call, as a less obvious error. If you
relied on catching that exception, validate before constructing.

## `getToken()` returns an array when unset

Previously `null`, now `[]`. Code written as

```php
if ($client->getToken() === null) { /* … */ }
```

no longer detects the "no token" case. Use `empty()` instead:

```php
if (!$client->getToken()) { /* … */ }
```

## Constructor arguments are explicitly nullable

`Http $client = null` became `?Http $client = null`, likewise for `$input`. This silences the
PHP 8.4 deprecation for implicitly nullable parameters; callers are unaffected.

## Dependency changes

| Package | v3 (3.0.0) | v4 (4.0.0) |
|---|---|---|
| `php` | `^8.1.0` | `^8.3.0` |
| `joomla/application` | `^3.0` | `^4.0` |
| `joomla/http` | `^3.0` | `^4.0` |
| `joomla/input` | `^3.0` | `^4.0` |
| `joomla/registry` | `^3.0` | `^4.0` |
| `joomla/session` | `^3.0` | `^4.0` |
| `joomla/uri` | `^3.0` | `^4.0` |
