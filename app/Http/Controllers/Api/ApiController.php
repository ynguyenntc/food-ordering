<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
//
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Password;
use Carbon\Carbon;

class ApiController extends Controller
{
    //API register(POST)
    public function register(Request $request)
    {
        $validateUser = Validator::make($request->all(), [
            "username"=> "required",
            // "email"=> "required|email|unique:users,email",
            "email"=> "required|string|email|max:255|unique:users",
            "password"=> "required",
        ]);

        if ($validateUser->fails()){
            return response()->json([
                "status"=> false,
                "message"=>'validation error',
                "error"=>$validateUser->errors()
                ]);
        }
        // try{
        //     $user = new User();
        //     $user->username = $request->username;
        //     $user->email = $request->email;
        //     $user->password = Hash::make($request->password);
        //     $user->save();
        // }
        

        $user = User::create([
            "username"=> $request->username,
            "email"=> $request->email,
            // "password"=>$request->password, 
            "password"=> Hash::make($request->password),
        ]);

        return response()->json([
            "status"=> true,
            "message"=> "User created successfully",
            // "token"=>$user->createToken("API TOKEN")->plainTextToken
        ]);
    }

    //API login (POST)
    public function login(Request $request)
    {

    }

    //API profile (GET)
    public function profile(Request $request)
    {

    }

    //logout
    public function logout(Request $request)
    {

    }

}
 //register, login, profile, login