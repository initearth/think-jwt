<?php

declare(strict_types=1);

namespace tests;

use think\Request;

/**
 * 轻量请求替身：避免对含 method() 的 Request 做 PHPUnit mock 触发弃用。
 */
final class FakeRequest extends Request
{
    public function __construct(private array $headers = [])
    {
    }

    public function header(string $name = '', ?string $default = null)
    {
        return $this->headers[$name] ?? $default;
    }
}
