<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StaffOnboardRequest extends FormRequest
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
            'terms-conditions.accepted' => 'You must Agree to Vodacom Terms & Conditions !'
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
}
