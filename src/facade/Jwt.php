<?php

declare(strict_types=1);

namespace think\facade;

use think\Facade;

/**
 * ThinkPHP 8.0+ Jwt 验证
 * @see \think\Jwt
 * @package think\facade\Jwt
 * @mixin \think\Jwt
 * @method static mixed|string|\Exception getToken($data = []) 获取token
 * @method static mixed|array Check($token = '') 验证令牌(Token)的有效性
 * @method static mixed|array Refresh($token = '') 刷新令牌
 * @method static mixed|array Logout($token = '') 注销令牌
 * @method static mixed|array|\Exception Parse($token = '', $type = 0) 解析并验证JWT令牌
 * @method static mixed|string getRequestHeaders() 获取请求头中的Authorization字段,用于提取token
 * @method static mixed|string getRequestToken(\think\Request $request) 从请求中获取授权令牌（仅 Authorization Bearer 头）
 * @method static mixed|string getClientToken() 从请求中获取令牌（仅 Authorization Bearer 头）
 */
class Jwt extends Facade
{
    public const SUCCESS = 1; //业务成功码，与 \think\Jwt::SUCCESS 一致
    public const ENCRYPT_EORROR = 50001;
    public const JWT_SECRET_MISS = 50002;
    public const INVALID_TOKEN = 40001;
    public const SIGNATURE_INVALID = 40002;
    public const TOKEN_NOT_YET_VALID = 40003;
    public const PAYLOAD_INVALID = 40004;
    public const TOKEN_MISSING = 40005;
    public const TOKEN_EXPIRE = 20001;
    public const TOKEN_EXPIRE_LONG = 20002;
    public const TOKEN_LOGOUT = 20003;
    public const TOKEN_DOMAIN = 20004;

    protected static function getFacadeClass()
    {
        return \think\Jwt::class;
    }
}
