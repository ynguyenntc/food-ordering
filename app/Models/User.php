<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
// use Laravel\Sanctum\HasApiTokens;
use Laravel\Passport\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'fullname',
        'username',
        'email',
        'password',
        'address',
        'gender',
        'dob',
        'role',
    ];

    // auto create id
    // protected static function boot()
    // {
    //     parent::boot();
    //     self::creating((function ($model) {
    //         $getUser = self::orderBy('id', 'desc')->first();
    //         if($getUser){
    //             $lastestID = intval(substr($getUser->id,3));
    //             $nextID = $lastestID + 1;
    //         } else {
    //             $nextID = 1;
    //         }
    //         $model->id = 'User_'. sprintf("%03s",$nextID);
    //         while (self::where("id",$model->id)->exists()) {
    //             $nextID++;
    //             $model->id = "User_". sprintf("%03s",$nextID);
    //         }

    // }));
// }
    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
    ];
}
