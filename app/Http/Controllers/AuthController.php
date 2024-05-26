<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Token;

class AuthController extends Controller
{
    public function register(Request $request){
        $validator = $request->validate([
            'name' => 'required|string',
            'email' => 'required|unique:users',
            'password' => 'required|string|min:6'
        ]);

        $input = $request->all();
        $input['password'] = Hash::make($input['password']);
        $user = User::create($input);
        $success['token'] = $user->createToken('user_token')->accessToken;
        $success['message'] = "User Registration Successfully!";
        return response()->json(['data' => $success],200);
    }

    public function login(Request $request)
    {
        if ($request->header('Authorization')) {
            $token = $request->header('Authorization');
            $token = str_replace('Bearer ', '', $token);

            $tokenRecord = Token::where('id', $token)->where('revoked', false)->first();
            if ($tokenRecord) {
                $user = User::find($tokenRecord->user_id);
                Auth::login($user);
                return response()->json(['token' => $token], 200);
            }
        }
        $credentials = $request->only('email', 'password');
        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = $user->createToken('user_token')->accessToken;

            return response()->json(['token' => $token], 200);
        } else {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json(['message' => 'Successfully logged out']);
    }
}

