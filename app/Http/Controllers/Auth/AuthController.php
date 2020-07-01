<?php

namespace App\Http\Controllers\Auth;

use App\Helpers\JWTHelper;
use App\Http\Controllers\Controller;
use App\Models\Auth\Auth;
use App\Models\Auth\User;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{

    public function index(Request $request) :JsonResponse
    {
        $credential = JWTHelper::decode($request);
        return response()->json([
            'status' => 'true',
            'message' => 'Welcome '.$credential->user.', remaining time to access the application '.Carbon::createFromTimestamp($credential->exp)->diffForHumans()
        ], 200);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @param Request $request
     * @return JsonResponse
     * @throws ValidationException
     */
    public function login(Request $request) :JsonResponse
    {
        /**
         * Validasi tiap-tiap request
         */
        $this->validate($request, [
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        $fetch = User::query()->where('USRNM', '=', $request->input('username'));
        if ($fetch->exists()) {
            $fetchUser = $fetch->first();
            if (password_verify($request->input('password'), $fetchUser->PASWD)) {

                return response()->json(array_merge(['status' => true], Auth::createToken($fetchUser->USRNM)));
            } else {
                return response()->json([
                    'message' => 'These credentials do not match our records.',
                    'errors' => ['password' => ['These credentials do not match our records.',]]
                ], 401);
            }
        } else {
            return response()->json([
                'message' => 'These credentials do not match our records.',
                'errors' => ['username' => ['These credentials do not match our records.',]]
            ], 401);
        }
    }

    public function extendToken(Request $request) :JsonResponse
    {
        $this->validate($request, [
            'minute' => 'required|numeric'
        ]);

        try {
            $jwt = JWTHelper::decode($request);
            $expired = $jwt->exp;
            $payload = [
                'jti' => $jwt->jti,
                'iat' => $jwt->iat,
                'nbf' => $jwt->nbf,
                'exp' => Carbon::createFromTimestamp($expired)->addMinutes($request->input('minute', 0))->timestamp,
                'user' => $jwt->user,
                'role' => $jwt->role
            ];
            return response()->json([
                'status' => true,
                'message' => 'Successfully extend jwt token',
                'token' => JWT::encode($payload, env('JWT_SECRET'), env('JWT_ALGORITHM'))
            ]);
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
