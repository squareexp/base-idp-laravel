<?php

namespace SquareExp\IdpLaravel;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Client\Factory as HttpFactory;
use SquareExp\IdpLaravel\Contracts\SquarePrincipal;
use SquareExp\IdpLaravel\Exceptions\SquareIdpException;

final class SquareIdpManager
{
    private const ACCESS_IMPLICIT = 'square-experience:idp:access:v1';
    private const HEADER = 'v4.public.';

    public function __construct(
        private readonly array $config,
        private readonly HttpFactory $http,
        private readonly CacheRepository $cache,
    ) {
    }

    public function authorizeUrl(array $options = []): string
    {
        $query = [
            'response_type' => 'code',
            'client_id' => $this->requiredConfig('client_id'),
            'redirect_uri' => $options['redirect_uri'] ?? $this->requiredConfig('redirect_uri'),
            'scope' => $this->scopeString($options['scopes'] ?? $this->config['scopes'] ?? ''),
        ];

        foreach (['state', 'nonce', 'code_challenge'] as $key) {
            if (!empty($options[$key])) {
                $query[$key] = $options[$key];
            }
        }
        if (!empty($options['code_challenge'])) {
            $query['code_challenge_method'] = $options['code_challenge_method'] ?? 'S256';
        }

        return $this->issuer() . '/oauth2/authorize?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    public function exchangeCode(string $code, ?string $codeVerifier = null): array
    {
        $body = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->requiredConfig('client_id'),
            'redirect_uri' => $this->requiredConfig('redirect_uri'),
        ];
        if (!empty($this->config['client_secret'])) {
            $body['client_secret'] = $this->config['client_secret'];
        }
        if ($codeVerifier) {
            $body['code_verifier'] = $codeVerifier;
        }
        return $this->postToken($body);
    }

    public function refresh(string $refreshToken, array|string|null $scopes = null): array
    {
        $body = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->requiredConfig('client_id'),
        ];
        if (!empty($this->config['client_secret'])) {
            $body['client_secret'] = $this->config['client_secret'];
        }
        if ($scopes) {
            $body['scope'] = $this->scopeString($scopes);
        }
        return $this->postToken($body);
    }

    public function verifyAccessToken(string $token, ?string $requiredScope = null): SquarePrincipal
    {
        $parts = explode('.', $token);
        if (count($parts) !== 4 || $parts[0] !== 'v4' || $parts[1] !== 'public') {
            throw new SquareIdpException('invalid_token', 'Token is not PASETO v4.public');
        }

        $payload = $this->base64UrlDecode($parts[2]);
        $footerBytes = $this->base64UrlDecode($parts[3]);
        if (strlen($payload) <= SODIUM_CRYPTO_SIGN_BYTES) {
            throw new SquareIdpException('invalid_token', 'PASETO payload is too short');
        }

        $footer = json_decode($footerBytes, true, 32, JSON_THROW_ON_ERROR);
        if (($footer['alg'] ?? null) !== 'v4.public' || ($footer['typ'] ?? null) !== 'paseto' || empty($footer['kid'])) {
            throw new SquareIdpException('invalid_token', 'Unsupported PASETO footer');
        }

        $message = substr($payload, 0, -SODIUM_CRYPTO_SIGN_BYTES);
        $signature = substr($payload, -SODIUM_CRYPTO_SIGN_BYTES);
        $publicKey = $this->publicKeyForKid($footer['kid']);
        $pae = $this->preAuthEncode([self::HEADER, $message, $footerBytes, self::ACCESS_IMPLICIT]);

        if (!sodium_crypto_sign_verify_detached($signature, $pae, $publicKey)) {
            throw new SquareIdpException('invalid_signature', 'PASETO signature verification failed');
        }

        $claims = json_decode($message, true, 64, JSON_THROW_ON_ERROR);
        $this->validateClaims($claims, $requiredScope);

        return new SquarePrincipal(
            id: $claims['gid'],
            subject: $claims['sub'],
            email: $claims['email'] ?? null,
            name: $claims['name'] ?? null,
            role: $claims['role'],
            scopes: $claims['scp'] ?? [],
            accountContext: $claims['ctx'] ?? [],
            claims: $claims,
        );
    }

    public function publicKeys(bool $force = false): array
    {
        $cacheKey = 'square-idp:paseto-v4-public:' . sha1($this->issuer());
        if (!$force && ($cached = $this->cache->get($cacheKey))) {
            return $cached;
        }

        $response = $this->http->acceptJson()->get($this->issuer() . '/v1/keys/paseto-v4-public');
        if (!$response->successful()) {
            throw new SquareIdpException('key_fetch_failed', 'Base public-key endpoint rejected the request', $response->status(), $response->json());
        }
        $payload = $response->json();
        $ttl = (int) ($this->config['cache_ttl_seconds'] ?? 300);
        $this->cache->put($cacheKey, $payload, max(60, $ttl));
        return $payload;
    }

    private function postToken(array $body): array
    {
        $response = $this->http
            ->asForm()
            ->acceptJson()
            ->post($this->issuer() . '/oauth2/token', $body);

        if (!$response->successful()) {
            throw new SquareIdpException('token_exchange_failed', 'Base token endpoint rejected the request', $response->status(), $response->json());
        }

        return $response->json();
    }

    private function validateClaims(array $claims, ?string $requiredScope): void
    {
        if (($claims['token_use'] ?? null) !== 'access') {
            throw new SquareIdpException('invalid_claims', 'token_use must be access');
        }
        if (($claims['iss'] ?? null) !== $this->issuer() || ($claims['aud'] ?? null) !== ($this->config['audience'] ?? 'square-experience')) {
            throw new SquareIdpException('invalid_claims', 'Issuer or audience mismatch');
        }

        $now = time();
        $skew = (int) ($this->config['clock_skew_seconds'] ?? 30);
        if (strtotime($claims['exp'] ?? '') <= $now - $skew) {
            throw new SquareIdpException('token_expired', 'Access token expired');
        }
        if (strtotime($claims['nbf'] ?? '') > $now + $skew) {
            throw new SquareIdpException('token_not_yet_valid', 'Access token is not valid yet');
        }

        $scope = $requiredScope ?? ($this->config['required_scope'] ?? null);
        if ($scope && !in_array($scope, $claims['scp'] ?? [], true)) {
            throw new SquareIdpException('insufficient_scope', 'Required scope is missing');
        }
        foreach (['gid', 'sub', 'sid', 'ctx', 'role'] as $key) {
            if (empty($claims[$key])) {
                throw new SquareIdpException('invalid_claims', "Required claim {$key} is missing");
            }
        }
    }

    private function publicKeyForKid(string $kid): string
    {
        if (!empty($this->config['public_key_base64'])) {
            $decoded = $this->base64UrlDecode($this->config['public_key_base64']);
            if (strlen($decoded) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                return $decoded;
            }
        }

        foreach (($this->publicKeys()['keys'] ?? []) as $key) {
            if (($key['kid'] ?? null) === $kid && ($key['alg'] ?? null) === 'v4.public') {
                $decoded = $this->base64UrlDecode($key['public_key_base64'] ?? '');
                if (strlen($decoded) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    return $decoded;
                }
            }
        }
        throw new SquareIdpException('unknown_kid', 'PASETO key id is not present in the Base key set');
    }

    private function requiredConfig(string $key): string
    {
        $value = trim((string) ($this->config[$key] ?? ''));
        if ($value === '') {
            throw new SquareIdpException('invalid_config', "Missing square-idp config value: {$key}");
        }
        return $value;
    }

    private function issuer(): string
    {
        return rtrim((string) ($this->config['issuer'] ?? 'https://authlayer.squareexp.com'), '/');
    }

    private function scopeString(array|string $scopes): string
    {
        if (is_array($scopes)) {
            return implode(' ', array_values(array_filter($scopes)));
        }
        return trim(preg_replace('/\s+/', ' ', $scopes));
    }

    private function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if ($decoded === false) {
            throw new SquareIdpException('invalid_base64url', 'Invalid base64url value');
        }
        return $decoded;
    }

    private function preAuthEncode(array $pieces): string
    {
        $out = $this->uint64le(count($pieces));
        foreach ($pieces as $piece) {
            $out .= $this->uint64le(strlen($piece)) . $piece;
        }
        return $out;
    }

    private function uint64le(int $value): string
    {
        $out = '';
        for ($i = 0; $i < 8; $i++) {
            $out .= chr($value & 0xff);
            $value = intdiv($value, 256);
        }
        return $out;
    }
}
