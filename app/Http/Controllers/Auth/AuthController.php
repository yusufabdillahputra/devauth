<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\Auth\Auth;
use App\Models\Auth\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{

    /**
     * Get a JWT via given credentials.
     *
     * @param Request $request
     * @return JsonResponse
     * @throws ValidationException
     */
    public function login(Request $request)
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
                $JWT = Auth::createToken($fetchUser->USRNM);
                return response()->json([
                    'status' => true,
                    'type' => 'single_device',
                    'token' => $JWT
                ]);
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
}
