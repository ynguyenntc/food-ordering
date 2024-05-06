<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Dotenv\Exception\ValidationException;
use Illuminate\Http\Request;
use App\Models\PasswordReset;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Password;
use Illuminate\Support\Facades\RateLimiter;
use Laravel\Passport\Passport;
use Carbon\Carbon;
use Laravel\Passport\Token;
use Illuminate\Auth\SessionGuard;
use Illuminate\Support\Facades\Http;
use Laravel\Passport\TokenRepository;
use Exception;
use Illuminate\Support\Str;
use DB;




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
                "expires_in" => $token->token->expires_at->diffInSeconds(now()),
                "refresh_token" => $user->tokens->where('revoked', false)->first()->refresh_token,
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

    /**
     * @OA\Post(
     *     path="/api/logout",
     *     summary="Logout user",
     *     tags={"Authentication"},
     *     description="Invalidate the current user's token to logout",
     *     security={{ "bearerAuth":{} }},
     *     @OA\Response(
     *         response=200,
     *         description="Successful operation",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true, description="Indicates if the request was successful"),
     *             @OA\Property(property="message", type="string", example="Logout successfully", description="A message indicating the outcome of the request")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated", description="A message indicating that the request lacks valid authentication credentials")
     *         )
     *     )
     * )
     */

    //logout
    public function logout(Request $request)
    {
        $token = $request->user()->token();
        $token->revoke();
        return response()->json([
            "status"=> true,
            "message"=> "Logout successfully",
        ]);
    }

    //forgot password api
    public function forgotpassword(Request $request)
    {
        //check email user có tồn tại hay không
        $input = $request->all();
        $rules = array(
            'email' => "required|email|exists:users,email",
        );
        $validator = Validator::make($input, $rules);
        #nếu không, trả kết quả lỗi
        if ($validator->fails()){
            return response()->json([
                "status"=> false,
                // "message" => $validator->errors()->first(),
                "error"=>$validator->errors()
            ]);
        }
        else{
            $token = Str::random(20);
            try{
                
                $domain = URL::to('/');
                $url = $domain.'/reset-password?token='.$token;
                $data['url'] = $url;
                $data['email'] = $request->email;
                $data['title'] = "Password Reset";
                $data["body"] = "Please click here to reset your password ";

                // gửi thông báo qua mail cho user 
                Mail::send('forgotPasswordMail', ['data'=>$data],function($message)use ($data){
                    $message->to($data['email'])->subject($data['title']);
                });

                #lưu token và cập nhập email
                DB::table("password_reset_tokens")->updateOrInsert([
                    'email' => $request->email
                ], [
                'email' => $request->email,
                'token' => $token,
                'created_at' => now()
                ]);

                return response()->json([
                    "message" => "please check your email to reset your password!"
                ]);

        }catch(Exception $e){
            return response()->json([
                'success' => false,
                'message' => $e->getMessage()
            ]);
        }
        }

    }

    
    }
 //register, login, profile, logout, forgot