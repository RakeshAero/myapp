<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginRegisterController extends Controller
{
    //

    public function __construct()
    {
        $this->middleware('guest')->except([
            'logout', 'dashboard'
        ]);
    }

    public function register(){
        return view('auth.register');
    }

    public function login(){
        return view('auth.login');
    }


    public function store(Request $request){
        $request->validate([
            "name"=>"required|string|max:250",
            "email"=>"required|string|unique:users",
            "password"=>"required|confirmed|min:8"
        ]);

        User::create([
            "name" => $request->name,
            "email"=> $request->email,
            "password" => Hash::make($request->password)
        ]);

        $data = $request->only(["email","password"]);
        Auth::attempt($data);
        $request->session()->regenerate();

        return redirect()->route('dashboard')->withSuccess('You Have Successfully Loged in !');
    }

    public function authenticate(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if(Auth::attempt($credentials))
        {
            $request->session()->regenerate();
            return redirect()->route('dashboard')
                ->withSuccess('You have successfully logged in!');
        }

        return back()->withErrors([
            'email' => 'Your provided credentials do not match in our records.',
        ])->onlyInput('email');

    }


    public function dashboard()
    {
        if(Auth::check())
        {
            return view('auth.dashboard');
        }

        return redirect()->route('login')
            ->withErrors([
            'email' => 'Please login to access the dashboard.',
        ])->onlyInput('email');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect()->route('login')
            ->withSuccess('You have logged out successfully!');;
    }
}
