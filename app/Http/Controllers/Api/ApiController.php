<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Dotenv\Exception\ValidationException;
use Illuminate\Http\Request;
//
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Password;
// use Carbon\Carbon;

class ApiController extends Controller
{
    //API register(POST)
    public function register(Request $request)
    {
        //check input data 
        $validateUser = Validator::make($request->all(), [
            "username"=> "required",
            // "email"=> "required|email|unique:users,email",
            "email"=> "required|string|email|max:255|unique:users",
            "password"=> "required",
        ]);
        //if error, print all error and message
        if ($validateUser->fails()){
            return response()->json([
                "status"=> false,
                "message"=>'validation error',
                "error"=>$validateUser->errors()
                ]);
        }
        
        //create new user
        $user = User::create([
            "username"=> $request->username,
            "email"=> $request->email,
            // "password"=>$request->password, 
            "password"=> Hash::make($request->password),
        ]);

        //Notififation of successfull user creation
        return response()->json([
            "status"=> true,
            "message"=> "User created successfully",
            // "token"=>$user->createToken("API TOKEN")->plainTextToken
        ]);
    }

    //API login (POST)
    public function login(Request $request)
    {
        // // check input data
        // $request->validate([
        //     "email" => "required|email",
        //     "password" => "required"
        // ]);

        // // check login
        // $token = Auth::attempt([
        //     "email" => $request->email,
        //     "password" => $request->password
        // ]); 
        // if(!empty($token)){
        //     return response()->json([
        //         "status" => true,
        //         "message" => "Login Succesfull",
        //         "token" => $token
        //     ]);
        // }
        // else {
        //     return response()->json([
        //         "status" => false,
        //         "message" => "Invalid Credentials",
        //     ]);
        // }
         // Data validation
         $request->validate([
            "email" => "required|email",
            "password" => "required"
        ]);

        // Auth Facade
        if(Auth::attempt([
            "email" => $request->email,
            "password" => $request->password
        ])){
       
            $user = Auth::user();

            $token = $user->createToken("myToken")->accessToken;

            return response()->json([
                "status" => true,
                "message" => "Login successful",
                "access_token" => $token
            ]);
        }

        return response()->json([
            "status" => false,
            "message" => "Invalid credentials"
        ]);

    }


    //API profile (GET)
    public function profile()
    {
        $user = Auth::user();
        return response()->json([
            "status"=> true,
            "message"=> "Show profile user",
            "data" => $user
        ]);
        
    }

    //logout
    public function logout()
    {

    }

}
 //register, login, profile, login