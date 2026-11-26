<?php

declare(strict_types=1);

namespace tests;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use think\Jwt as ThinkJwt;

final class JwtTest extends TestCase
{
    private const SECRET = 'test-secret-with-at-least-32-bytes';

    protected function tearDown(): void
    {
        unset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
    }

    public function testGetTokenAndParseRoundTrip(): void
    {
        $jwt = $this->jwt();

        $token = $jwt->getToken(['user_id' => 12]);
        $this->assertCount(3, explode('.', $token));

        $full = $jwt->Parse($token, 1);
        $this->assertSame(12, $full['data']['user_id']);
        $this->assertArrayHasKey('jwt_ide', $full);
        $this->assertArrayHasKey('nbf', $full);
        $this->assertArrayHasKey('exp', $full);
        $this->assertSame(['user_id' => 12], $jwt->Parse($token));
    }

    public function testTamperedSignatureThrowsSignatureInvalidCode(): void
    {
        $jwt = $this->jwt();
        $parts = explode('.', $jwt->getToken(['user_id' => 1]));
        $parts[2][0] = $parts[2][0] === 'A' ? 'B' : 'A';
        $tampered = implode('.', $parts);

        try {
            $jwt->Parse($tampered);
            $this->fail('篡改签名后应抛出异常');
        } catch (\Exception $e) {
            $this->assertSame(ThinkJwt::SIGNATURE_INVALID, $e->getCode());
            $this->assertStringContainsString('签名无效', $e->getMessage());
        }
    }

    public function testExpiredTokenThrowsExpireLongCode(): void
    {
        $jwt = $this->jwt();
        $token = $this->sign([
            'nbf'     => time() - 1000,
            'exp'     => time() - 10,
            'jwt_ide' => 'expired-id',
            'data'    => ['user_id' => 1],
        ]);

        try {
            $jwt->Parse($token);
            $this->fail('已过期令牌应抛出异常');
        } catch (\Exception $e) {
            $this->assertSame(ThinkJwt::TOKEN_EXPIRE_LONG, $e->getCode());
            $this->assertStringContainsString('令牌已过期', $e->getMessage());
        }
    }

    public function testBeforeValidTokenThrowsNotYetValidCode(): void
    {
        $jwt = $this->jwt();
        $token = $this->sign([
            'nbf'     => time() + 3600,
            'exp'     => time() + 7200,
            'jwt_ide' => 'future-id',
            'data'    => ['user_id' => 1],
        ]);

        try {
            $jwt->Parse($token);
            $this->fail('尚未生效的令牌应抛出异常');
        } catch (\Exception $e) {
            $this->assertSame(ThinkJwt::TOKEN_NOT_YET_VALID, $e->getCode());
            $this->assertStringContainsString('令牌尚未生效', $e->getMessage());
        }
    }

    public function testCheckUsesRefreshThreshold(): void
    {
        $jwt = $this->jwt(60);
        $token = $this->sign([
            'nbf'     => time() - 120,
            'exp'     => time() + 3600,
            'jwt_ide' => 'old-id',
            'data'    => ['user_id' => 1],
        ]);

        $res = $jwt->Check($token);
        $this->assertSame(['status', 'code', 'message', 'data', 'error'], array_keys($res));
        $this->assertSame('error', $res['status']);
        $this->assertSame(401, $res['code']);
        $this->assertSame('token过期需要刷新', $res['message']);

        $fresh = $jwt->getToken(['user_id' => 2]);
        $this->assertSame(200, $jwt->Check($fresh)['code']);
    }

    public function testCheckReturnsErrorCodeForMissingToken(): void
    {
        $res = $this->jwt()->Check('');
        $this->assertSame(400, $res['code']);
        $this->assertSame('未提供令牌', $res['message']);
    }

    public function testCheckReturnsErrorCodeForMalformedToken(): void
    {
        $res = $this->jwt()->Check('not-a-token');
        $this->assertSame(400, $res['code']);
    }

    public function testRefreshAndLogoutBlacklistOldToken(): void
    {
        $jwt = $this->jwt();
        $token = $jwt->getToken(['user_id' => 7]);

        $res = $jwt->Refresh($token);
        $this->assertSame(['status', 'code', 'message', 'data', 'error'], array_keys($res));
        $this->assertSame(200, $res['code']);
        $this->assertNotSame($token, $res['data']);
        $this->assertSame(['user_id' => 7], $jwt->Parse($res['data']));

        try {
            $jwt->Parse($token);
            $this->fail('刷新后的旧令牌应进入黑名单');
        } catch (\Exception $e) {
            $this->assertSame(ThinkJwt::TOKEN_LOGOUT, $e->getCode());
        }

        $logout = $jwt->Logout($res['data']);
        $this->assertSame(['status', 'code', 'message', 'data', 'error'], array_keys($logout));
        $this->assertSame(200, $logout['code']);
        try {
            $jwt->Parse($res['data']);
            $this->fail('注销后的令牌应进入黑名单');
        } catch (\Exception $e) {
            $this->assertSame(ThinkJwt::TOKEN_LOGOUT, $e->getCode());
        }
    }

    public function testGetRequestHeadersStrictlyParsesBearer(): void
    {
        $jwt = $this->jwt();

        $_SERVER['HTTP_AUTHORIZATION'] = 'bearer abc.def.ghi';
        $this->assertSame('abc.def.ghi', $jwt->getRequestHeaders());

        $_SERVER['HTTP_AUTHORIZATION'] = 'Basic abc.def.ghi';
        $this->assertSame('', $jwt->getRequestHeaders());

        unset($_SERVER['HTTP_AUTHORIZATION']);
        $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] = 'Bearer redirected.token.value';
        $this->assertSame('redirected.token.value', $jwt->getRequestHeaders());
    }

    public function testGetRequestTokenUsesRequestAndFallbackHeaders(): void
    {
        $jwt = $this->jwt();

        $request = new FakeRequest(['authorization' => 'Bearer direct.token.value']);
        $this->assertSame('direct.token.value', $jwt->getRequestToken($request));

        $request = new FakeRequest(['HTTP_AUTHORIZATION' => 'Bearer fallback.token.value']);
        $this->assertSame('fallback.token.value', $jwt->getRequestToken($request));
    }

    public function testGetClientTokenReadsHeaderOnly(): void
    {
        $jwt = $this->jwt();

        $this->assertSame('', $jwt->getClientToken());
        $this->assertSame('', $jwt->getRequestToken(new FakeRequest([])));

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer header-token';
        $this->assertSame('header-token', $jwt->getClientToken());
        $this->assertSame('header-token', $jwt->getRequestHeaders());

        unset($_SERVER['HTTP_AUTHORIZATION']);
        $this->assertSame('', $jwt->getClientToken());
    }

    public function testParseRejectsPayloadWithoutRequiredFields(): void
    {
        $jwt = $this->jwt();
        $token = $this->sign([
            'nbf'  => time(),
            'exp'  => time() + 3600,
            'data' => ['user_id' => 1],
        ]);

        try {
            $jwt->Parse($token);
            $this->fail('缺少 jwt_ide 的令牌应被拒绝');
        } catch (\Exception $e) {
            $this->assertSame(ThinkJwt::PAYLOAD_INVALID, $e->getCode());
            $this->assertStringContainsString('必要字段', $e->getMessage());
        }
    }

    public function testRandomAndObjectToArrayHandleEdgeCases(): void
    {
        $jwt = $this->jwt();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $jwt->Random());
        $this->assertSame([], $jwt->objectToArray(new \stdClass()));
        $this->assertSame(['a' => ['b' => 1]], $jwt->objectToArray(json_decode('{"a":{"b":1}}')));
    }

    public function testMissingSecretThrowsAtConstruction(): void
    {
        try {
            new TestableJwt(['secret' => '']);
            $this->fail('空密钥应在构造时抛出异常');
        } catch (\Exception $e) {
            $this->assertSame(ThinkJwt::JWT_SECRET_MISS, $e->getCode());
        }
    }

    private function jwt(int $exp = 36000, int $refresh = 604800): TestableJwt
    {
        return new TestableJwt([
            'secret'  => self::SECRET,
            'exp'     => $exp,
            'refresh' => $refresh,
        ]);
    }

    private function sign(array $payload): string
    {
        return JWT::encode($payload, self::SECRET, 'HS256');
    }
}
