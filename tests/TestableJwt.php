<?php

declare(strict_types=1);

namespace tests;

use think\Jwt;

/**
 * 用内存黑名单和可注入配置替代框架全局 config()/cache()，便于单元测试。
 */
final class TestableJwt extends Jwt
{
    /** @var array<string, bool> */
    public array $blacklist = [];

    public function __construct(array $cfg = [])
    {
        $this->cfg = $cfg;
        $this->secret = (string) ($cfg['secret'] ?? '');
        $this->exp = (int) ($cfg['exp'] ?? 36000);
        $this->refresh = (int) ($cfg['refresh'] ?? 604800);

        if ($this->secret === '') {
            throw new \Exception('未设置jwt秘钥', self::JWT_SECRET_MISS);
        }
    }

    protected function InBlacklist($jwt_ide = '')
    {
        return isset($this->blacklist[$jwt_ide]);
    }

    protected function AddBlacklist($jwt_ide = '')
    {
        $this->blacklist[$jwt_ide] = true;
        return true;
    }
}
