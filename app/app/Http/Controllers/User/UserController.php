<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\UserLoginRequest;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use GuzzleHttp\Client;
use Validator;
use Session;

class UserController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
    }

    public function showLoginForm()
    {
        //session::flush();
        if ($this->IsLoggedIn()) {
            return redirect()->intended(route('home'));
        }
        return view('auth.login');
    }

    /**
     * Handles Login Request
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(UserLoginRequest $request)
    {
        if (session::has('lockedUser')) {
            $badUser = session::get('lockedUser');
            if ($badUser['name'] == $request->name) {
                $remainingTime = time() - $badUser['time'];
                if ($remainingTime < 180) {
                    $newTime = $badUser['time'] + 180;
                    if ((($newTime - time()) / 60) >= 1) {
                        $toTime = ceil(($newTime - time()) / 60) . ' minutes !';
                    } else {
                        $toTime = $newTime - time() . ' seconds !';
                    }

                    return back()->withErrors(['message' => 'Your account is locked for ' . $toTime]);
                } else {
                    session::flush();
                }
            }
        }



        // $key = 'user:' . $request->name;

        // if ($this->redis->exists($key)) {
        //     $this->redis->del($key);
        // }

        $body = [
            'UserName' => $request->name,
            'Password' => $request->password,
            'platform' => 'web',
            'AppVersion' => null
        ];

        $url = 'login';

        $data = $this->postRequest($url, $body);

        if (isset($data['Token']) && empty($data['Error'])) {

            $request->session()->flush();
            $request->session()->put('user', $data);

            if ($data['ChangePassword'] === true) {
                return redirect()->route('recover.new.password');
            }

            return redirect()->route('otp');
        } elseif ($data['Code'] == "122") {
            $maxCount = 3;

            if (session::has('uname')) {
                if (session::get('count') <= $maxCount) {

                    if (session::get('uname') == $request->name) {
                        $attempts = session::get('count');
                        $attempts++;
                        session::put('count', $attempts);
                    } else {
                        session::put('uname', $request->name);
                        session::put('count', 1);
                    }

                    if (session::get('count') == $maxCount) {
                        session::forget('remaining');
                        $time = time();
                        $lockedUser = [
                            'name' => $request->name,
                            'time' => $time
                        ];
                        session::put('lockedUser', $lockedUser);
                        $this->lockUser($request->name);
                        return back()->withErrors(['message' => 'You have reached maximum login attempts. Your account is locked for 30 mins !']);
                    }
                }
            } else {
                session::put('uname', $request->name);
                session::put('count', 1);
            }

            $remaining = $maxCount - session::get('count');
            session::put('remaining', $remaining);

            return back()->withErrors('Oops! Invalid Username or Password !');
        } elseif ($data['Code'] == "121") {
            return back()->withErrors('Oops! Invalid Username or Password !');
        } elseif ($data['Code'] == "123") {
            return back()->withErrors('Oops! Your Account has been locked !');
        }

        return back()->withErrors('Sorry! Something went wrong !');
    }

    /**
     * Handles OTP Login Form
     *
     * @return Shows to OTP form on success
     */
    public function showOTPForm()
    {
        if ($this->IsLoggedIn()) {
            redirect()->intended(route('home'));
        } elseif (isset($this->user)) {
            $len = substr($this->user['Phone'], 0, 6) . '***' . substr($this->user['Phone'], 9, 3);
            return view('auth.otp', ['msisdn' => $len]);
        } else {
            return redirect()->route('login');
        }
    }

    public function validateOtp(UserLoginRequest $request)
    {
        if (!$request->validated()) {
            return back();
        }

        $body = [
            'ID' => $this->user['UserID'],
            'Description' => $request->otp,
            'IPAddress' => $request->ip(),
            'Platform' => 'web',
        ];

        $url = 'otp';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] == '0' && $data['Description'] == 'OK') {
            $request->session()->put('Authenticated', TRUE);

            // $this->redis->hmset('user:' . $this->user['UserName'], [
            //     'username' => $this->user['UserName'],
            //     'token' => $this->user['Token'],
            //     'hash_created_at' => date('Y-m-d H:i:s')
            // ]);

            return redirect()->intended(route('home'));
        }

        return back()->withErrors('Oops! Invalid OTP. Please Try again!');
    }

    public function logoutUser()
    {
        $body = ['UserID' => $this->user['UserID']];

        $url = 'LogOut';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] !== 0) {
            Log::channel('Logout')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'TimeStamp' => time(), 'Response' => $data]);
        }

        session::flush();

        return redirect('login')->withWarning("You have been logged out !");
    }

    public function IsLoggedIn()
    {
        if (session::has('user')) {
            if (session::has('Authenticated')) {
                return TRUE;
            }
            return FALSE;
        }
        return FALSE;
    }

    public function resendToken(Request $request)
    {
        if ($this->IsLoggedIn()) {
            abort(403);
        }

        $body = [
            'UserID' => $this->user['UserID'],
            'Email' => $this->user['Email'],
            'Phone' => $this->user['Phone']
        ];

        $url = 'ResendOTP';

        $data = $this->postRequest($url, $body);

        if (isset($data['ID']) && $data['ID'] == $this->user['UserID']) {
            if (isset($data['Description']) && $data['Description'] == 'OK') {
                return back();
            }
        }

        $request->session()->flush();
        return redirect()->route('login')->withErrors(['Oops! Something went wrong. Please Login again!']);
    }

    public function showResetPassword()
    {
        return view('auth.reset-password');
    }

    public function showRecoverPassword()
    {
        return view('auth.recover-password');
    }

    public function RecoverPassword(UserLoginRequest $request)
    {
        if ($request->inputEmail1 !== $request->inputEmail2) {
            return redirect()->back()->withErrors(['Passwords do not match. Please Try again !']);
        }

        $body = [
            'UserID' => session::get('userId'),
            'Password' => $request->inputEmail2,
            'ResetPasswordToken' => session::get('token')
        ];

        $url = 'ResetPassword';

        $data = $this->postRequest($url, $body);

        session::flush();

        if (isset($data)) {
            if ($data['Description'] == 'OK') {
                return redirect('/')->with('warning', "Your password has been reset !");
            } else {
                return redirect()->route('login')->withErrors(['Oops! Email does does not exist. Please Try again !']);
            }
        }

        return redirect()->route('login')->withErrors(['Oops! Something went wrong. Please Try again !']);
    }

    protected function verifyResetPasswordToken($token)
    {
        $body = [
            'Token' => $token
        ];

        $url = 'CheckResetPasswordToken';

        $data = $this->postRequest($url, $body);

        if (isset($data) && $data['ID'] !== "0" && $data['Description'] == 'OK') {
            session::put('userId', $data['ID']);
            session::put('token', $token);
            return redirect()->route('recover.password');
        }

        return redirect()->route('login')->withErrors(['Oops! Token has expired. Please Try again !']);
    }

    public function showRecoverNewPassword()
    {
        return view('auth.recover-new-password');
    }

    public function RecoverNewPassword(Request $request)
    {
        $body = [
            'UserID' => $this->user['UserID'],
            'OldPassword' => $request->inputpwdOld,
            'NewPassword' => $request->inputpwdNew,
        ];

        $url = 'ResetDefaultPwd';

        $data = $this->postRequest($url, $body);

        session::flush();

        if ($data['ID'] === 1 && $data['Description'] == 'OK') {
            return redirect('/')->with('info', "Your password has been reset !");
        } elseif ($data['ID'] == 2 || $data['ID'] == 3) {
            return back()->withErrors('Password Already Used Before. Please use Another !');
        } elseif ($data['ID'] == 0) {
            return back()->withErrors('Wrong Password . Please use Another try Again !');
        }

        return redirect()->route('login')->withErrors(['Oops! Something went wrong. Please Try again !']);
    }

    public function showRecoverPasswordSMS()
    {
        return view('auth.recover-password-sms');
    }

    public function RecoverPasswordSMS(UserLoginRequest $request)
    {
        $body = [
            'Msisdn' => $request->get('reset_password_phone'),
        ];

        $url = 'ResetPwdByPhone';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] === 0 && $data['Description'] === null) {
            return redirect('/')->with('info', "Your password has been reset !");
        } elseif ($data['Description'] !== null) {
            return redirect()->back()->withErrors('Wrong Phone number ! ')->withInput();
        }

        return redirect()->route('login')->withErrors(['Oops! Something went wrong. Please Try again !']);
    }

    private function lockUser($userName)
    {
        $body = [
            'username' => $userName,
        ];

        $url = 'LockUser';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] == 0 && $data['Description'] == null) {
            return TRUE;
        }

        return FALSE;
    }

    public function ShowCreateNewUser()
    {
        $url = 'GetUserRoles';
        $data = $this->getRequest($url);

        $url2 = 'GetUsersList';
        $users = $this->getRequest($url2);

        return view('users.create-new')->with(['roles' => $data, 'users' => $users]);
    }

    public function CreateNewUser(Request $request)
    {
        $messages = [
            'userName.required' => 'Please Input UserName !',
            'mobile-phone.required' => 'Please Input User\'s Phone Number !',
            'mobile-phone.regex' => 'Invalid User\'s Phone Number !',
            'email.required' => 'Please Input User\'s Email Adress !',
            'email.email' => 'Invalid User\'s Email Adress !',
            'roleName.required' => 'Please Select User\'s Role !',
        ];

        $this->validate($request, [
            'userName' => 'required',
            'mobile-phone' => 'required|regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})/',
            'email' => 'required|email',
            'roleName' => 'required',
        ], $messages);


        $body = [
            'CreatedBy' => $this->user['UserID'],
            'username' => $request->userName,
            'phone' => $request->get('mobile-phone'),
            'email' => $request->email,
            'IsAD' => $request->isAD ? 'Y' : "N",
            'ActiveYN' => $request->isActive ? 'Y' : "N",
            'roleID' => (int) $request->roleName,
        ];

        $url = 'CreateUser';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 0) {
            return response()
                ->json([
                    'message' => 'User Successful Created !',
                    'status' => $data['ID']
                ], 200);
        } elseif ($data['ID'] == 2) {
            return response()
                ->json([
                    'message' => 'User already exists in the system !',
                    'status' => $data['ID']
                ], 200);
        }

        return response()
            ->json([
                'message' => 'Sorry, Something went wrong . Try again !',
            ], 400);
    }
}
