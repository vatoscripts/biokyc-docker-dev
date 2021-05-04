<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class OneSIMKYCRequest extends FormRequest
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
        if ($this->is('one-sim/new-reg-post') ) {
            return $this->NewRegStartRules();
        }

        // Check if New Minor rules
        elseif ($this->is('one-sim/new-reg-primary-post')) {
            return $this->NewRegPrimaryNIDARules();
        }

        // Check if New Minor rules
        elseif ($this->is('one-sim/new-reg-secondary-post')) {
            return $this->NewRegSecondaryNIDARules();
        }

        // Check if New Diplomat rules
        if ($this->is('one-sim/diplomat/new-reg-post') ) {
            return $this->NewDiplomatRegStartRules();
        }

        // Check if Single Diplomat Primary rules
        if ($this->is('one-sim/diplomat/new-reg-primary-post') ) {
            return $this->NewDiplomatRegPrimaryRules();
        }

        // Check if Single Diplomat Primary rules
        if ($this->is('one-sim/diplomat/new-reg-secondary-post') ) {
            return $this->NewDiplomatRegSecondaryRules();
        }

        // Check if New Visitor rules
        if ($this->is('one-sim/visitor/new-reg-post') ) {
            return $this->NewVisitorRegStartRules();
        }

        // Check if Visitor Primary rules
        if ($this->is('one-sim/visitor/new-reg-primary-post') ) {
            return $this->NewVisitorRegPrimaryRules();
        }

        // Check if Visitor Primary rules
        if ($this->is('one-sim/visitor/new-reg-secondary-post') ) {
            return $this->NewVisitorRegSecondaryRules();
        }

        // Check if Bulk rules
        if ($this->is('api/one-sim/bulk/new-reg-post') ) {
            return $this->NewBulkRegStartRules();
        }

        // Check if Bulk search rules
        if ($this->is('api/one-sim/bulk/new-reg-search') ) {
            return $this->NewBulkRegSearchRules();
        }

         // Check if Bulk primary spoc rules
        if ($this->is('api/one-sim/bulk/primary-spoc') ) {
            return $this->NewBulkRegPrimarySpocRules();
        }
    }


    private function NewRegStartRules()
    {
        return [
            'msisdn' => 'required|regex:/^(0)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required | digits:20',
        ];
    }

    private function NewRegPrimaryNIDARules()
    {
        return [
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ];
    }

    private function NewRegSecondaryNIDARules()
    {
        return [
            'fingerCode' => 'required',
            'fingerData' => 'required',
            'tcraReason' => 'required'
        ];
    }

    private function NewDiplomatRegStartRules()
    {
        return [
            'msisdn' => 'required|regex:/^(0)-?([0-9]{3})-?([0-9]{6})$/',
            'passportNumber' => 'required',
        ];
    }

    private function NewVisitorRegStartRules()
    {
        return [
            'msisdn' => 'required|regex:/^(0)-?([0-9]{3})-?([0-9]{6})$/',
            'passportNumber' => 'required',
        ];
    }

    private function NewDiplomatRegPrimaryRules()
    {
        return [
            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',

            'id-number' => 'required',
            'gender' => 'required',
            'institution' => 'required',
            'dob' => 'required',

            'country' => 'required',
            'front-id-file' => 'required|max:200|mimes:jpeg,jpg,png',
            'back-id-file' => 'required|max:200|mimes:jpeg,jpg,png',
            'passport-file' => 'required|max:200|mimes:jpeg,jpg,png'
        ];
    }

    private function NewDiplomatRegSecondaryRules()
    {
        return [
            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',

            'id-number' => 'required',
            'gender' => 'required',
            'institution' => 'required',
            'dob' => 'required',

            'country' => 'required',
            'front-id-file' => 'required|max:200|mimes:jpeg,jpg,png',
            'back-id-file' => 'required|max:200|mimes:jpeg,jpg,png',
            'passport-file' => 'required|max:200|mimes:jpeg,jpg,png',

            'tcraReason' => 'required'
        ];
    }

    private function NewVisitorRegPrimaryRules()
    {
        return [
            'issuingCountry' => 'required',
            'fingerCode' => 'required',
            'fingerData' => 'required',
        ];
    }

    private function NewVisitorRegSecondaryRules()
    {
        return [
            'tcraReason' => 'required',
            'issuingCountry' => 'required',
            'fingerCode' => 'required',
            'fingerData' => 'required',
        ];
    }

    private function NewBulkRegStartRules()
    {
        return [
            'companyName' => 'required',
        ];
    }

    private function NewBulkRegSearchRules()
    {
        return [
            'company' => 'required',
        ];
    }

    private function NewBulkRegPrimarySpocRules()
    {
        return [
            'spocEmail' => 'required|email',
            'spocMsisdn' => 'required|regex:/^\+?(255)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required',
            // 'region' => 'required',
            // 'district' => 'required',
            // 'ward' => 'required',
            'village' => 'required',
            //'expiry-date' => 'required',
        ];
    }

    public function messages()
    {
        return [
            /** START PAGE **/
            'msisdn.required' => 'Please Input Customer\'s phone number !',
            'msisdn.regex' => 'Invalid Customer\'s phone number !',
            'NIN.required' => 'Please Input Customer\'s NIDA ID !',
            'NIN.digits' => 'Invalid Customer\'s NIDA ID Format !',

            /** NEW PRIMARY MSISDN **/
            'fingerCode.required' => 'Please Select Customer\'s finger index !',
            'fingerData.required' => 'Please Capture Customer\'s finger print !',

            /** NEW SECONDARY MSISDN **/
            'fingerCode.required' => 'Please select Customer\'s finger index !',
            'fingerData.required' => 'Please capture Customer\'s finger print !',
            'tcraReason.required' => 'Please select TCRA reason !',

            /** START DIPLOMAT PAGE **/
            'msisdn.required' => 'Please input Customer\'s phone number !',
            'msisdn.regex' => 'Invalid Customer\'s phone number !',
            'passportNumber.required' => 'Please input Customer\'s passport number !',

            /** Single Diplomat */
            'firstName.required' => 'Please input first name !',
            'middleName.required' => 'Please input middle name !',
            'lastName.required' => 'Please input last name !',
            'dob.required' => 'Please input Date of birth !',

            'id-number.required' => 'Please input diplomat ID number !',
            'gender.required' => 'Please select gender !',
            'institution.required' => 'Please input Institution name !',

            'country.required' => 'Please Select Country !',
            'front-id-file.required' => 'Please upload scanned diplomat ID front side !',
            'back-id-file.required' => 'Please upload scanned diplomat ID back side !',
            'passport-file.required' => 'Please upload scanned Passport !',

            'front-id-file.mimes' => 'Please upload correct diplomat ID document format, .PNG or .JPEG !',
            'back-id-file.mimes' => 'Please upload correct diplomat ID document format, .PNG or .JPEG !',
            'passport-file.mimes' => 'Please upload correct document format, .PNG or .JPEG !',

			'front-id-file.max' => 'Maximum upload file of size of 200KB exceeded !',
            'back-id-file.max' => 'Maximum upload file of size of 200KB exceeded !',
            'passport-file.max' => 'Maximum upload file of size of 200KB exceeded !',

            /** NEW VISITOR MSISDN  */
            'issuingCountry.required' => 'Please select issuing country code !',
            'tcraReason.required' => 'Please select TCRA reason !',

            /** NEW BULK MSISDN  */
            'companyName.required' => 'Please input company name !',

            /** NEW BULK SEARCH  */
            'company.required' => 'Please select company !',

            /** BULK REGISTRATION Page1 **/
            'spocEmail.required' => 'Please Input SPOC\'s email adress !',
            'spocEmail.email' => 'Invalid SPOC\'s email adress !',
            'spocMsisdn.required' => 'Please Input SPOC\'s phone number !',
            'spocMsisdn.email' => 'Invalid SPOC\'s phone number !',
            'NIN.required' => 'Please Input SPOC\'s NIDA ID !',
            'NIN.digits' => 'Invalid SPOC\'s NIDA ID Format !',
            'fingerCode.required' => 'Please Select SPOC\'s finger index !',
            'fingerData.required' => 'Please Capture SPOC\'s finger print !',
            'phoneNumber.required' => 'Please Input SPOC\'s phone number!',
            'phoneNumber.digits' => 'Invalid SPOC\'s phone number !',
            'phoneNumber.regex' => 'Invalid SPOC\'s phone number !',
            // 'region.required' => 'Please Select region !',
            // 'district.required' => 'Please Select district !',
            // 'ward.required' => 'Please Select ward !',
            'village.required' => 'Please Select street !',
            'expiry-date.required' => 'Please Input Expiry Date !',

        ];
    }
}
