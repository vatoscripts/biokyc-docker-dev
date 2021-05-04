<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class KYCReportsRequest extends FormRequest
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
        // Check if Registration Journey Rules
        if ($this->is('reports/customer-journey-download') ) {
            return $this->regJourneyRules();
        }

        // Check if MSISDN rules
        elseif ($this->is('check-msisdn') || $this->is('recheck-msisdn') || $this->is('search-registration') || $this->is('sim-swap-msisdn')) {
            return $this->checkMSISDNRules();
        }
    }

    private function regJourneyRules()
    {
        return [
            'startDate' => 'required',
            'endDate' => 'required',
            'reportType' => 'required'
        ];
    }

    public function messages()
    {
        return [
            'startDate.required' => 'Please Input Start Date !',
            'endDate.required' => 'Please Input End Date !',
            'reportType.required' => 'Please Select Report Type !',
        ];
    }
}
