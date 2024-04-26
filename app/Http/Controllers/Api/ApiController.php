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
use Illuminate\Support\Facades\RateLimiter;
use Laravel\Passport\Passport;
use Carbon\Carbon;
use Laravel\Passport\Token;
use Illuminate\Auth\SessionGuard;
use Illuminate\Support\Facades\Http;




class ApiController extends Controller
{
    // public function __construct() {
    //     $this->middleware('auth:api', ['except' => ['login', 'register']]);
    // }
    //API register(POST)

        /**
 * @OA\Post(
 *     path="/api/register",
 *     summary="Register a new user",
 *     tags={"Authentication"},
 *     @OA\RequestBody(
 *         required=true,
 *         @OA\MediaType(
 *             mediaType="application/json",
 *             @OA\Schema(
 *                 @OA\Property(
 *                     property="username",
 *                     type="string",
 *                     example="john_doe",
 *                     description="The username of the user."
 *                 ),
 *                 @OA\Property(
 *                     property="email",
 *                     type="string",
 *                     format="email",
 *                     example="john@example.com",
 *                     description="The email address of the user."
 *                 ),
 *                 @OA\Property(
 *                     property="password",
 *                     type="string",
 *                     example="password123",
 *                     description="The password of the user."
 *                 ),
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="User registered successfully",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="status",
 *                 type="boolean",
 *                 example=true
 *             ),
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="User created successfully"
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=422,
 *         description="Validation error",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="status",
 *                 type="boolean",
 *                 example=false
 *             ),
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Validation error"
 *             ),
 *             @OA\Property(
 *                 property="error",
 *                 type="object",
 *                 description="Validation errors",
 *                 example={"email": {"The email field is required."}}
 *             )
 *         )
 *     )
 * )
 */
    
    public function register(Request $request)
    {
        //check input data 
        $validateUser = Validator::make($request->all(), [
            "username"=> "required",
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



    
/**
 * @OA\Post(
 *     path="/api/login",
 *     summary="Authenticate user",
 *     tags={"Authentication"},
 *     @OA\RequestBody(
 *         required=true,
 *         @OA\MediaType(
 *             mediaType="application/json",
 *             @OA\Schema(
 *                 @OA\Property(
 *                     property="email",
 *                     type="string",
 *                     format="email",
 *                     example="john@example.com",
 *                     description="The email address of the user."
 *                 ),
 *                 @OA\Property(
 *                     property="password",
 *                     type="string",
 *                     example="password123",
 *                     description="The password of the user."
 *                 ),
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="Login successful",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="status",
 *                 type="boolean",
 *                 example=true
 *             ),
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Login successful"
 *             ),
 *             @OA\Property(
 *                 property="access_token",
 *                 type="string",
 *                 example="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6ImRiNGExMWE5MzU2MTYyNzVjMmFkNTQxNDc1Y2I4YzU4NTcxMTVmZjRhNDE0OGIzNjE4NzY0OTkxOWRjMDNlNGM0ZmI3NTVhYjZmNzJkOWI2In0..."
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=429,
 *         description="Too many login attempts",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="success",
 *                 type="boolean",
 *                 example=false
 *             ),
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Too many login attempts. Please try again in 60 seconds."
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=401,
 *         description="Invalid credentials",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="status",
 *                 type="boolean",
 *                 example=false
 *             ),
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Invalid credentials"
 *             )
 *         )
 *     )
 * )
 */

    public function login(Request $request)
    {
        //Limit 5 login/minute/email
        if (RateLimiter::tooManyAttempts('send-message:'.$request->email, $perMinute = 5)) {
            $seconds = RateLimiter::availableIn('send-message:'.$request->email);
         
            return response()->json([
                "success" => false,
                "message" => "Too many login attempts. Please try again in $seconds seconds.",
            ]);
        }           
        RateLimiter::increment('send-message:'.$request->email);
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

            $token = $user->createToken("myToken");
            // $accessTokenId = $user->tokens->last()->id;
            // $accessToken = Token::find($accessTokenId);
            // $expirationTime = Carbon::parse($accessToken->expires_at);
            return response()->json([
                "status" => true,
                "message" => "Login successful",
                "access_token" => $token->accessToken,
                // $ttlSeconds = auth()->factory()->getTTL() * 60;
                // "expires_at" => $token->getTTL() * 60


            ]);
        }

        return response()->json([
            "status" => false,
            "message" => "Invalid credentials"
        ]);

    }

     

/**
 * @OA\Get(
 *     path="/api/profile",
 *     summary="Get user profile",
 *     tags={"Profile"},
 *     security={{"bearerAuth": {}}},
 *     @OA\Response(
 *         response=200,
 *         description="User profile retrieved successfully",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="status",
 *                 type="boolean",
 *                 example=true
 *             ),
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Show profile user"
 *             ),
 *             @OA\Property(
 *                 property="data",
 *                 type="object",
 *                 example={"fullname":null, "username": "ynguyenntc", "email": "ynguyenntc@gmail.com","address": null,"gender": null,"dob": null,"role": null}
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=401,
 *         description="Unauthenticated",
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="status",
 *                 type="boolean",
 *                 example=false
 *             ),
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="Unauthenticated"
 *             )
 *         )
 *     )
 * )
 */


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

    //refresh accesstoken
    public function refreshToken()
    {
        // if(auth()->user()->token != null) {
        if(auth()->user()){
            // $response = Http::asForm()->post('http://localhost:8000/api/refresh', [
            //     'grant_type' => 'refresh_token',
            //     'refresh_token' => 'the-refresh-token',
            //     'client_id' => 'client-id',
            //     'client_secret' => 'client-secret',
            //     'scope' => '',
            // ]);
            // return $response->json();
            // auth()->user()->token()->refresh();
            $newToken = Auth::parseToken()->refresh();
        }
        else{
            return response()->json([
                'success' => false,
                'message' => "User is not Authenticated"]) ;
        }
        
    }

}
 //register, login, profile, login