<?php

declare(strict_types=1);

namespace app\controller;

use Initearth\ThinkResponse\Facade\Response;
use think\facade\Jwt;
use think\Response as ThinkResponse;

/**
 * 令牌签发 / 校验 / 刷新 / 注销 示例
 *
 * Check / Refresh / Logout 直接返回 think-response 标准结构
 */
class Auth
{
    /**
     * 签发令牌
     */
    public function create(): ThinkResponse
    {
        $token = Jwt::getToken([
            'user_id'  => 12,
            'username' => 'initearth',
        ]);

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
