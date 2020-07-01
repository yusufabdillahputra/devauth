<?php

namespace App\Models\Auth;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class Auth extends Model
{

    /**
     * @param $username (Bisa dirubah sesuai projek)
     * @return array
     *
     * todo : tiap projek menyesuaikan apakah menggunakan username , oid atau lainnya
     */
    public static function createToken($username) {

        $fetchRole = UserRoleRelation::query()
            ->select('ROLCD')
            ->where('USRNM', '=', $username)
            ->get()
            ->toArray();

        /**
         * Type : Bisa disesuaikan
         */
        $payload = [
            'jti' => Str::random(),
            'iat' => Carbon::now()->getTimestamp(),
            'nbf' => Carbon::now()->getTimestamp(),
            'exp' => strtotime('+1 day'),
            'user' => $username,
            'role' => !empty($fetchRole) ? $fetchRole : null
        ];

        /**
         * Type : fixed
         */
        $JWT = JWT::encode($payload, env('JWT_SECRET'), env('JWT_ALGORITHM'));

        /**
         * NOTE : Response berikut bisa di sesuaikan dengan kebutuhan project
         */
        return [
            'token_type' => 'Bearer',
            'expires_in' => Carbon::createFromTimestamp($payload['exp'])->diffForHumans(),
            'pernr' => $username,
            'access_token' => $JWT
        ];
    }

}
