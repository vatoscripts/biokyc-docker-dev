<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class AgentRequest extends FormRequest
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
        // Check if Agent Onboard rules Page 1
        if ($this->is('agents-nida')) {
            return $this->onboardAgent_page1();
        }

        // Check if Agent Onboard rules Page 2
        if ($this->is('create-agent')) {
            return $this->onboardAgent_page2();
        }

    }

    /**
     * Custom message for validation
     *
     * @return array
     */
    public function messages()
    {
        return [
            /** AGENT ONBOARD Page1*/
            'NIN.required' => 'Please Input Agent\'s NIDA ID !',
            'NIN.digits' => 'Invalid Agent\'s NIDA ID Format !',
            'fingerCode.required' => 'Please Select Agent\'s finger index !',
            'fingerData.required' => 'Please Capture Agent\'s finger print !',

            /** AGENT ONBOARD Page2*/
            'business-name.required' => 'Please Input Agent\'s Business or Company name!',
            'TIN.required' => 'Please Input Agent\'s TIN number!',
            'TIN.numeric' => 'Invalid Agent\'s TIN number!',
            'business-licence.required' => 'Please Input Agent\'s Business Licence number!',
            'business-location.required' => 'Please Input Agent\'s Business Location!',
            'mobile-phone.required' => 'Please Input Agent\'s Mobile phone number!',
            'mobile-phone.regex' => 'Invalid Agent\'s Mobile phone number format!',
            'business-phone.required' => 'Please Input Agent\'s Business Phone number!',
            'TIN-file.required' => 'Please Upload Agent\'s TIN Licence file!',
            'TIN-file.mimes' => 'Agent\'s TIN Licence file must be in PDF format!',
            'TIN-file.max' => 'Agent\'s TIN Licence Max file Size of 2MB Exceeded !',
            'business-licence-file.required' => 'Please Upload Agent\'s Business Licence file!',
            'business-licence-file.mimes' => 'Agent\'s Business Licence file must be in PDF format!',
            'business-licence-file.max' => 'Agent\'s Business Max file Size of 2MB Exceeded !',
            'email.required' => 'Please Input Agent\'s E-mail Adress!',
            'agent-category.required' => 'Please Input Agent\'s Channel Type!',
        ];
    }

    private function onboardAgent_page1()
    {
        return [
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ];
    }

    private function onboardAgent_page2()
    {
        return [
            'business-name' => 'required|string',
            //'TIN' => 'required|numeric',
            //'business-licence' => 'required|string',
            'business-location' => 'required',
            'mobile-phone' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/',
            'business-phone' => 'required|digits_between:10,12|numeric',
            'TIN-file' => 'mimes:pdf|max:2048',
            'business-licence-file' => 'mimes:pdf|max:2048',
            'email' => 'required|email',
            //'agent-category' => 'required',
        ];
    }
}
