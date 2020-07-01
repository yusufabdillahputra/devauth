<?php

namespace App\Http\Middleware;

use App\Models\Auth\User;
use Closure;
use Exception;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;

class JSONWebToken
{
    /**
     * Handle an incoming request.
     *
     * @param  Request  $request
     * @param  Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $EXP_Bearer = explode('Bearer ', $request->header('Authorization'));
        $JWT = !empty($EXP_Bearer[1]) ? $EXP_Bearer[1] : null ;

        if (!$JWT) {
            return response()->json([
                'status' => false,
                'message' => 'Token not provided'
            ], 401);
        }

        try {
            $credential = JWT::decode($JWT, env('JWT_SECRET'), [env('JWT_ALGORITHM')]);
            /**
             * Query dibawah bisa diambil untuk kebutuhan data sesi login
             */
            $fetchUser = User::query()->where('USRNM', '=', $credential->user)->first();
            $request->AuthSession = $fetchUser;
            return $next($request);
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
