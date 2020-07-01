<?php

namespace App\Models\Auth;

use Illuminate\Database\Eloquent\Model;

class UserRoleRelation extends Model
{
    protected $table = 'USERROLERELATION';

    protected $primaryKey = 'oid';

    protected $guarded = [];

    protected $hidden = [];

    public $incrementing = false;

    public $timestamps = false;

}
