<?php

namespace App\Helpers;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;

class JWTHelper
{
    const __HEADER_TOKEN = 'Authorization';

    public static function getToken(Request $request)
    {
        $EXP_Bearer = explode('Bearer ', $request->header(self::__HEADER_TOKEN));
        $JWT = !empty($EXP_Bearer[1]) ? $EXP_Bearer[1] : null;
        return $JWT;
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse|object
     */
    public static function decode(Request $request)
    {
        $JWT = self::getToken($request);
        if (!$JWT) {
            return response()->json([
                'status' => false,
                'message' => 'Token not provided'
            ], 401);
        }
        try {
            return JWT::decode($JWT, env('JWT_SECRET'), [env('JWT_ALGORITHM')]);
        } catch (ExpiredException $expiredException) {
            return response()->json([
                'status' => false,
                'message' => 'Provided token is expired'
            ], 400);
        } catch (Exception $exception) {
            return response()->json([
                'status' => false,
                'message' => 'An error while decoding token.'
            ], 400);
        }
    }
}
