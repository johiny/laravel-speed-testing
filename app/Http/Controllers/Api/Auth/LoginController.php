<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response as HttpResponse;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum')->only('logout');
    }

    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'message' => $validator->errors(),
                ], HttpResponse::HTTP_UNPROCESSABLE_ENTITY);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                    'message' => 'incorect email or password',
                ], HttpResponse::HTTP_UNPROCESSABLE_ENTITY);
            }

            return response()->json([
                'data' => [
                    'user' => $user,
                    'access_token' => $user->createToken($request->email)->plainTextToken
                ],
                'message' => 'token has been created.',
            ], HttpResponse::HTTP_OK);
        } catch (\Exception $e) {

            return response()->json([
                'message' => $e->getMessage()
            ], HttpResponse::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function logout(Request $request)
    {
        try {

            // Revoke all tokens...
            // $user->tokens()->delete();

            // Revoke the token that was used to authenticate the current request...
            $request->user()->currentAccessToken()->delete();

            // Revoke a specific token...
            // $request->user()->tokens()->where('id', $tokenId)->delete();

            return response()->json([
                'message' => 'all token has been revoked from this user.',
            ], HttpResponse::HTTP_OK);
        } catch (\Exception $e) {

            return response()->json([
                'message' => $e->getMessage()
            ], HttpResponse::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    //SPA FUNCTIONS

//     public function login(Request $request)
//     {
//         $credentials = $request->validate([
//             'email' => ['required', 'email'],
//             'password' => ['required'],
//         ]);

//         if (!Auth::attempt($credentials)) {
//             return response()->json([
//                 'message' => 'invalid email or password'
//             ]);

//         }
//         return response()->json([
//             'data' => $request->user(),
//             'message' => 'user logged in'
//         ]);
//     }

//     public function logout(Request $request){

//     Auth::logout();
//     return response()->json([
//         'message' => "user has been logged out"
//     ]);
// }
}
