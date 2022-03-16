<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Response as HttpResponse;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

class ResetPasswordController extends Controller
{
    public function sendResetPasswordLink(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'message' => $validator->errors(),
                ], HttpResponse::HTTP_UNPROCESSABLE_ENTITY);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return response()->json([
                    'message' => 'incorect email.',
                ], HttpResponse::HTTP_UNPROCESSABLE_ENTITY);
            }

            $sendResetLinkStatus = Password::sendResetLink($request->only('email'));

            if ($sendResetLinkStatus === Password::RESET_LINK_SENT) {
                return response()->json([
                    'message' => 'reset password link has been sent.',
                ], HttpResponse::HTTP_OK);
            }

            return response()->json([
                'message' => 'reset password link has been failed to send.'
            ], HttpResponse::HTTP_UNPROCESSABLE_ENTITY);
        } catch (\Exception $e) {

            return response()->json([
                'message' => $e->getMessage()
            ], HttpResponse::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function resetPassword(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'token' => 'required',
                'email' => 'required|email',
                'password' => 'required|min:6|confirmed',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'message' => $validator->errors(),
                ], HttpResponse::HTTP_UNPROCESSABLE_ENTITY);
            }

            $passwordResetStatus = Password::reset(
                $request->only([
                    'email',
                    'password',
                    'password_confirmation',
                    'token'
                ]),
                function ($user, $password) {
                    $user->forceFill([
                        'password' => Hash::make($password)
                    ])->setRememberToken(Str::random(60));

                    $user->save();

                    event(new PasswordReset($user));
                }
            );

            if ($passwordResetStatus == Password::PASSWORD_RESET) {
                return response()->json([
                    'message' => 'password has been reset.'
                ], HttpResponse::HTTP_CREATED);
            }

            return response()->json([
                'message' => 'invalid token given.'
            ], HttpResponse::HTTP_UNPROCESSABLE_ENTITY);
        } catch (\Exception $e) {

            return response()->json([
                'message' => $e->getMessage()
            ], HttpResponse::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
