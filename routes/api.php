<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\ApiController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

//Register
Route::post("register",[ApiController::class,"register"]);

//login
Route::post("login",[ApiController::class,"login"]);
//profile

// Route::post("/logout",[ApiController::class,"logout"])->middleware('auth:api');

Route::group([
    "middleware" => 'auth:api',
], function(){

    Route::get("profile", [ApiController::class, "profile"]);
    Route::post("logout", [ApiController::class, "logout"]);
    Route::get("refresh", [ApiController::class,"refreshToken"]);
});