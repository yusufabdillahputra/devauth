<?php

namespace App\Models\Auth;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    protected $table = 'USER';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'USRNM',
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'PASWD',
    ];
}
