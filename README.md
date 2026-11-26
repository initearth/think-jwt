# think-jwt

基于 [firebase/php-jwt](https://github.com/firebase/php-jwt) 的 **ThinkPHP 8** JWT 认证扩展，开箱即用，支持令牌签发、验证、刷新与注销（黑名单）。

## 特性

- 仅支持 **ThinkPHP 8**（不兼容 ThinkPHP 6）
- 基于 `firebase/php-jwt ^7.2`，默认 `HS256` 算法
- `Facade` 门面调用，一行代码即可签发 / 校验
- 令牌唯一标识（`jwt_ide`），配合缓存实现刷新与注销黑名单
- 返回结构采用 `initearth/think-response` 标准模式：`status / code / message / data / error`
- 完整错误码，便于前端统一处理

## 环境要求

| 依赖 | 版本 |
| --- | --- |
| PHP | `>= 8.2` |
| ThinkPHP | `^8.0` |
| firebase/php-jwt | `^7.2` |

## 安装

```sh
composer require initearth/think-jwt
```

安装后包配置会自动加载，不会覆盖应用已有的同名配置。请在 `.env` 中设置 `JWT_SECRET`；如需覆盖，可复制 `examples/config/jwt.php` 到应用 `config/jwt.php`。

## 配置

```php
<?php

declare(strict_types=1);

return [
    // 加密密钥，从 .env 读取，必须设置，否则构造时抛出异常
    'secret'  => env('JWT_SECRET', ''),
    // 刷新阈值（秒），用于判断令牌是否需要刷新，默认 10 小时
    'exp'     => (60 * 60) * 10,
    // 令牌有效期（秒），同时作为黑名单缓存时长，默认 7 天
    'refresh' => ((60 * 60) * 24) * 7,
];
```

> `JWT_SECRET` 为空时，`Jwt` 实例化即抛出 `未设置jwt秘钥`（错误码 `50002`）。请务必使用足够随机的密钥，不要使用示例中的默认字符串。

## 快速开始

```php
<?php

namespace app\controller;

use Initearth\ThinkResponse\Facade\Response;
use think\facade\Jwt;
use think\Response as ThinkResponse;

class Auth
{
    /**
     * 签发令牌
     */
    public function create(): ThinkResponse
    {
        $token = Jwt::getToken(['user_id' => 12]);

        return Response::success(['token' => $token], '签发成功');
    }

    /**
     * 校验令牌
     */
    public function check(): ThinkResponse
    {
        return json(Jwt::Check(Jwt::getClientToken()));
    }

    /**
     * 刷新令牌
     */
    public function refresh(): ThinkResponse
    {
        return json(Jwt::Refresh(Jwt::getClientToken()));
    }

    /**
     * 注销令牌
     */
    public function logout(): ThinkResponse
    {
        return json(Jwt::Logout(Jwt::getClientToken()));
    }
}
```

客户端传递方式仅支持请求头：

```http
Authorization: Bearer <token>
```

`Bearer` 大小写不敏感，但必须严格是 `Bearer <token>` 格式，其他格式返回空字符串。

## API

| 方法 | 说明 | 返回 |
| --- | --- | --- |
| `getToken(array $data = [])` | 签发令牌，`$data` 为自定义载荷 | `string` JWT |
| `Check(string $token = '')` | 校验令牌有效性 | `array` `{status, code, message, data, error}` |
| `Refresh(string $token = '')` | 刷新令牌，旧令牌加入黑名单 | `array` `{status, code, message, data, error}` |
| `Logout(string $token = '')` | 注销令牌，加入黑名单 | `array` `{status, code, message, data, error}` |
| `Parse(string $token = '', int $type = 0)` | 解析令牌，`$type=0` 返回 `data`，`$type=1` 返回完整载荷 | `array` |
| `getRequestHeaders()` | 仅从 `$_SERVER['HTTP_AUTHORIZATION']` / `REDIRECT_HTTP_AUTHORIZATION` 严格提取 Bearer 令牌 | `string` |
| `getRequestToken(\think\Request $request)` | 从请求对象提取令牌，仅读 Authorization Bearer 头（含备用头） | `string` |
| `getClientToken()` | 从请求中提取令牌，仅读 Authorization Bearer 头，无需 Request 对象 | `string` |

### 返回结构

`Check`、`Refresh`、`Logout` 在库层面直接使用 `initearth/think-response` 的 `Formatter` 输出标准五字段结构：

```php
[
    'status'  => 'success', // success / error / fail
    'code'    => 200,       // 映射后的响应码
    'message' => '操作成功',
    'data'    => [],        // 业务数据或新令牌
    'error'   => [],        // 错误详情
]
```

Jwt 内部错误码映射规则：

- 成功 → `200`
- `50001` / `50002` → `500`
- `20001` ~ `20004` → `401`
- 其他错误码 → `400`

控制器可直接返回：

```php
return json(Jwt::Check(Jwt::getClientToken()));
```

成功响应：

```json
{
  "status": "success",
  "code": 200,
  "message": "操作成功",
  "data": {"user_id": 12},
  "error": {}
}
```

失败响应：

```json
{
  "status": "error",
  "code": 401,
  "message": "token已被注销",
  "data": {},
  "error": {}
}
```

### Parse 返回

```php
// $type = 0（默认）返回自定义业务数据
Jwt::Parse($token);

// $type = 1 返回完整载荷
// ['nbf' => ..., 'exp' => ..., 'jwt_ide' => ..., 'data' => [...]]
Jwt::Parse($token, 1);
```

## 错误码

| 常量 | 值 | 说明 |
| --- | --- | --- |
| `SUCCESS` | `1` | 业务成功码 |
| `ENCRYPT_EORROR` | `50001` | 签发失败（对应 `JWT::encode()` 抛出的异常） |
| `JWT_SECRET_MISS` | `50002` | 未设置 JWT 密钥（对应 `InvalidArgumentException`） |
| `INVALID_TOKEN` | `40001` | 令牌格式异常（对应 `UnexpectedValueException`） |
| `SIGNATURE_INVALID` | `40002` | 签名无效（对应 `SignatureInvalidException`） |
| `TOKEN_NOT_YET_VALID` | `40003` | 令牌尚未生效（对应 `BeforeValidException`） |
| `PAYLOAD_INVALID` | `40004` | 载荷缺少 `jwt_ide` / `data` 等必要字段 |
| `TOKEN_MISSING` | `40005` | 未提供令牌 |
| `TOKEN_EXPIRE` | `20001` | 令牌签发时长超过刷新阈值，需要刷新 |
| `TOKEN_EXPIRE_LONG` | `20002` | 令牌已过期（对应 `ExpiredException`） |
| `TOKEN_LOGOUT` | `20003` | 令牌已被注销（命中缓存黑名单） |
| `TOKEN_DOMAIN` | `20004` | 算法 / 密钥 / JSON 处理异常（对应 `DomainException`） |

`Parse()` 以异常码形式抛出错误，可通过 `$e->getCode()` 获取下表常量；`Check()` / `Refresh()` / `Logout()` 返回的 `message` 保留原始错误信息，`code` 则是映射后的响应码：

```php
try {
    Jwt::Parse($token);
} catch (\Exception $e) {
    return json(['code' => $e->getCode(), 'msg' => $e->getMessage()]);
}
```

## 黑名单机制

刷新与注销时，令牌的唯一标识 `jwt_ide` 会写入缓存（键名 `jwt_ide_{id}`，时长与 `refresh` 一致）。后续 `Parse` / `Check` 时命中缓存即判定令牌已注销。

> 请确保应用已配置缓存驱动，并保证多节点部署时缓存共享。

## 示例

完整示例见 [`examples/`](examples) 目录：

| 文件 | 说明 |
| --- | --- |
| `examples/config/jwt.php` | 配置文件模板，复制到应用 `config/jwt.php` 后按需覆盖 |
| `examples/controller/Auth.php` | 签发 / 校验 / 刷新 / 注销控制器 |
| `examples/middleware/JwtAuth.php` | 令牌鉴权中间件 |

路由注册（`route/app.php`）：

```php
use think\facade\Route;

Route::post('auth/create', 'Auth/create');
Route::get('auth/check', 'Auth/check');
Route::post('auth/refresh', 'Auth/refresh');
Route::post('auth/logout', 'Auth/logout');

// 需要鉴权的接口分组
Route::group('api', function () {
    // ...
})->middleware(\app\middleware\JwtAuth::class);
```

## 测试

```sh
composer install
composer test
```

## ThinkPHP-PanGu - 盘古ThinkPHP开源索引!
面向 ThinkPHP 的开源工程索引：组件、框架、服务与发布工具，按能力组织，持续整理。
仓库地址：**<https://github.com/initearth/ThinkPHP-PanGu/>**
在线站点：**<https://initearth.github.io/ThinkPHP-PanGu/>**
