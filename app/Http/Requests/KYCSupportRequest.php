<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class KYCSupportRequest extends FormRequest
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
        // Check if NIDA rules i.e NIN, fingerData & fingerIndex
        if ($this->is('api/support/reg-details-id') ) {
            return $this->IDRegSupportRules();
        }

        if ($this->is('api/support/visitor-alternative-registrations/review') ) {
            return $this->VisitorAlternativeRegRules();
        }
    }

    private function IDRegSupportRules()
    {
        return [
            'reportType' => 'required',
            'idNumber' => 'required',
        ];
    }

    private function VisitorAlternativeRegRules()
    {
        return [
            'declineReason' => 'required_if:verificationStatus,3'
        ];
    }

    public function messages()
    {
        return [
            'reportType.required' => 'Please select report category !',
            'idNumber.required' => 'Please input customer\'s ID number !',
            'declineReason.required_if' => 'Please input decline reason !'
        ];
    }

}
