<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UserLoginRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        // Check if Login rules
        if ($this->is('login')) {
            return $this->loginRules();
        }
        // Check if OTP rules
        elseif ($this->is('otp')) {
            return $this->OtpRules();
        }
        // Check if reset-password rules
        elseif ($this->is('reset-password')) {
            return $this->resetPasswordRules();
        }
        // Check if recover-password rules
        elseif ($this->is('recover-password')) {
            return $this->recoverPasswordRules();
        }
        // Check if recover-new-password rules
        elseif ($this->is('recover-new-password')) {
            return $this->recoverNewPasswordRules();
        }
        // Check if recover-password-sms rules
        elseif ($this->is('recover-password-sms')) {
            return $this->recoverPasswordSMSRules();
        }
        // Check if create-new-user rules
        elseif ($this->is('create-new-user')) {
            return $this->createNewUserRules();
        }
    }

    public function messages()
    {
        return [
            'name.required' => 'Username is required !',
            'password.required' => 'Password is required !',
            'otp.required' => 'OTP is required !',
            'reset_password_email.required' => 'Email is required !',
            'inputpwd1.required' => 'New Password is required !',
            'inputpwd2.required' => 'Confirm new Password is required !',
            'terms-conditions.accepted' => 'You must Agree to Vodacom Terms & Conditions !',
            'inputpwdOld.required' => 'Token Password is required !',
            'inputpwdNew.required' => 'New Password is required !',
            'inputpwdNewConfirm.required' => 'Confirm Password is required !',
            'reset_password_phone.required' => 'We need to know your Phone Number !',
            'reset_password_phone.regex' => 'Invalid Phone Number. Try Again !',
            'inputpwdNewConfirm.same' => 'New password and confirm new password does not match !',
            'inputpwdNew.regex' => 'Password does not meet minimum security compliance !',
            'otp.digits' => 'Invalid OTP !'
        ];
    }

    public function loginRules()
    {
        return [
            'name' => 'required|string|max:20',
            'password' => 'required',
            'terms-conditions' => 'accepted'
        ];
    }

    public function OtpRules()
    {
        return [
            'otp' => 'required|digits:6'
        ];
    }

    public function resetPasswordRules()
    {
        return [
            'reset_password_email' => 'required|string|max:30'
        ];
    }

    public function recoverPasswordRules()
    {
        return [
            'inputpwd1' => 'required|string|max:30',
            'inputpwd2' => 'required|string|max:30|same:inputpwd1',
        ];
    }

    public function recoverNewPasswordRules()
    {
        return [
            'inputpwdOld' => 'required|string|max:30',
            'inputpwdNew' => 'required|string|min:10|regex:/^.*(?=.{10,})((?=.*[!@#$%^&*()\-_=+{};:,<.>]){1})(?=.*\d)((?=.*[a-z]){1})((?=.*[A-Z]){1}).*$/',
            'inputpwdNewConfirm' => 'required|string|min:10|max:30|same:inputpwdNew',
        ];
    }

    public function recoverPasswordSMSRules()
    {
        return [
            'reset_password_phone' => 'required|regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})/',
        ];
    }

    private function createNewUserRules()
    {
        return [

        ];
    }
}
