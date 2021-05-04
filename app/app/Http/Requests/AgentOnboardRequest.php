<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class AgentOnboardRequest extends FormRequest
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
        return [
            'mobile-phone' => 'required|numeric',
            'TIN' => 'required|numeric',
            'TIN-file' => 'required|file',
            'business-licence' => 'required|string',
            'business-licence-file' => 'required|file',
            'business-name' => 'required|string',
            'business-phone' => 'required|numeric',
            'business-location' => 'required|string',
            'email' => 'required|email',
            'NIN' => 'required|numeric',
        ];
    }

    /**
     * Custom message for validation
     *
     * @return array
     */
    public function messages()
    {
        return [
            'mobile-phone.required' => 'Mobile phone is required!',
            'TIN.required' => 'TIN is required!',
            'TIN-file.required' => 'TIN file is required!',
            'business-licence.required' => 'Business licence is required!',
            'business-licence-file.required' => 'Business licence file is required!',
            'business-name-file.required' => 'Business name file is required!',
            'business-name.required' => 'Business name is required!',
            'business-phone.required' => 'Business phone is required!',
            'business-location.required' => 'Business location is required!',
            'email.required' => 'Email is required!',
            'NIN.required' => 'NIN is required!'

        ];
    }
}
