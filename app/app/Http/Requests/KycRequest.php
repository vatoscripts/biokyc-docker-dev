<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class KycRequest extends FormRequest
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
        if ($this->is('re-register-msisdn') || $this->is('register-new-msisdn') || $this->is('sim-swap-save')) {
            return $this->NIDARules();
        }

        // Check if MSISDN rules
        elseif ($this->is('check-msisdn') || $this->is('recheck-msisdn') || $this->is('search-registration') || $this->is('sim-swap-msisdn')) {
            return $this->checkMSISDNRules();
        }
        // Check if New Minor rules
        elseif ($this->is('minor-registration-post1')) {
            return $this->checkNewMinorRules_page1();
        }

        // Check if New Minor rules
        elseif ($this->is('minor-registration-post2')) {
            return $this->checkNewMinorRules_page2();
        }
        // Check if Single Diplomat rules1
        elseif ($this->is('diplomat-registration-post')) {
            return $this->checkDiplomatRules();
        }
        // Check if Bulk Diplomat rules1
        elseif ($this->is('diplomat-registration-bulk-post1')) {
            return $this->checBulkkDiplomatRules_page1();
        }
        // Check if Bulk Diplomat rules2
        elseif ($this->is('diplomat-registration-bulk-post2')) {
            return $this->checBulkkDiplomatRules_page2();
        }
        // Check if Total Mismatch rules
        elseif ($this->is('registration-total-mismatch')) {
            return $this->totalMismatchRules();
        }
    }

    private function newRegRules()
    {
        return [
            'phoneNumber' => 'required|numeric'
        ];
    }

    private function SIMSwapRegRules()
    {
        return [
            'ICCID' => 'required|digits:20'
        ];
    }

    private function checkMSISDNRules()
    {
        return [
            'phoneNumber' => 'required |regex:/\+?(0)-?([0-9]{3})-?([0-9]{6})$/ | digits:10'
        ];
    }

    private function bulkRegRules_page1()
    {
        return [
            'spocEmail' => 'required|email',
            'spocMsisdn' => 'required|regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required',
            'region' => 'required',
            'district' => 'required',
            'ward' => 'required',
            'village' => 'required',
            'expiry-date' => 'required',
        ];
    }

    private function bulkRegRules_page2()
    {
        return [
            'business-name' => 'required|string',
            'MSISDN-file' => 'required|mimes:csv,txt',
            'company-email' => 'required|email',
            'registrationCategory' => 'required',

            'TIN' => 'numeric',
            'TIN-file' => 'mimes:jpeg,jpg,png',
            'business-licence-file' => 'mimes:jpeg,jpg,png',
            'business-licence' => 'numeric',
            'BRELA-file' => 'mimes:jpeg,jpg,png',
            'spoc-attachment-file' => 'mimes:jpeg,jpg,png',

            'TIN' => 'required_if:registrationCategory,COMP,CEMP',
            'TIN-file' => 'required_if:registrationCategory,COMP,CEMP',
            'business-licence-file' => 'required_if:registrationCategory,COMP,CEMP',
            'business-licence' => 'required_if:registrationCategory,COMP,CEMP',
            'BRELA-file' => 'required_if:registrationCategory,COMP,CEMP',
            'spoc-attachment-file' => 'required_if:registrationCategory,INST',
        ];
    }


    private function NIDARules()
    {
        return [
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ];
    }

    private function checkNewMinorRules_page1() {
        return [
            'guardian-msisdn' => 'required |regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})$/',
            'minor-relationship' => 'required',
            'guardian-NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ];
    }

    private function checkNewMinorRules_page2() {
        return [
            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',
            'dob' => 'required|regex:/\+?([0-31]{2})-?([0-12]{2})-?([1900-2020]{4})$/',

            'gender' => 'required',
            'ID-select' => 'required',
            'ID-number' => 'required',
            'country' => 'required',

            'minor-ID-photo-file' => 'required|mimes:jpeg,jpg,png',
            'minor-potrait-photo-file' => 'required|mimes:jpeg,jpg,png',
        ];
    }

    private function checkDiplomatRules()
    {
        return [
            'msisdn' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/',
            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',

            'passport-number' => 'required',
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

    private function checBulkkDiplomatRules_page1()
    {
        return [
            'region' => 'required',
            'district' => 'required',
            'ward' => 'required',
            'village' => 'required',
            'institution' => 'required',
            'adress' => 'required',
            'post-code'=> 'required|numeric',

            'msisdn-file' => 'required|mimes:csv,txt',
        ];
    }

    private function checBulkkDiplomatRules_page2()
    {
        return [
            'msisdn' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/',
            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',

            'passport-number' => 'required',
            'id-number' => 'required',
            'gender' => 'required',
            //'institution' => 'required',
            'dob' => 'required',
            'expiry-date' => 'required',
            'email' => 'required|email',

            'country' => 'required',
            'front-id-file' => 'required|max:200|mimes:jpeg,jpg,png',
            'back-id-file' => 'required|max:200|mimes:jpeg,jpg,png',
            'passport-file' => 'required|max:200|mimes:jpeg,jpg,png'
        ];
    }

    private function totalMismatchRules()
    {
        return [
            'OTP' => 'required | digits:6',
        ];
    }

    public function messages()
    {
        return [
            /** BULK REGISTRATION Page2*/
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
            'region.required' => 'Please Select region !',
            'district.required' => 'Please Select district !',
            'ward.required' => 'Please Select ward !',
            'village.required' => 'Please Select street !',
            'expiry-date.required' => 'Please Input Expiry Date !',

            /** BULK REGISTRATION Page2*/
            'business-name.required' => 'Please Input Business or Company name !',
            'spoc-attachment-file.required_if' => 'Please Input Company\'s SPOC attachment file !',
            'MSISDN-file.mimes' => 'Company\'s phone numbers file must be in CSV format !',
            'MSISDN-file.required' => 'Please Input Company\'s phone numbers file !',
            'spoc-attachment-file.mimes' => 'Company\'s SPOC attachment must be in PDF format !',
            'company-email.required' => 'Please Input Company\'s E-mail Adress !',
            'company-email.email' => 'Invalid Company\'s E-mail Adress format !',

            'TIN.required_if' => 'Please Input Company TIN number !',
            'TIN-file.required_if' => 'Please Input Company\'s SPOC attachment file !',
            'TIN-file.mimes' => 'Company\'s TIN file must be in PDF format !',
            'business-licence.required_if' => 'Please Input Company\'s Business Licence numbers !',
            'business-licence-file.required_if' => 'Please Input Company\'s Business Licence file !',
            'business-licence-file.mimes' => 'Company\'s Business Licence file must be in PDF format !',
            'BRELA-file.required_if' => 'Please Input Company\'s BRELA file !',
            'BRELA-file.mimes' => 'Company\'s BRELA file must be in PDF format !',
            'registrationCategory.required' => 'Please Input Registration category !',


            /** NIDA */
            'NIN.required' => 'Please Input Customer\'s NIDA ID !',
            'NIN.digits' => 'Invalid Customer\'s NIDA ID Format !',
            'fingerCode.required' => 'Please Input Customer\'s finger index !',
            'fingerData.required' => 'Please Input Customer\'s finger print !',

            /** MSISDN */
            'phoneNumber.required' => 'Please Input Customer\'s phone number!',
            'phoneNumber.digits' => 'Invalid Customer\'s phone number !',
            'phoneNumber.regex' => 'Invalid Customer\'s phone number !',

            /** ICCID */
            'ICCID.required' => 'Please Input SIM\'s ICCID number!',
            'ICCID.digits' => 'Invalid SIM\'s ICCID number !',

            /** New Minor Page1 */
            'guardian-msisdn.required' => 'Please Input Guardian\'s phone number!',
            'guardian-msisdn.regex' => 'Invalid Guardian\'s phone number !',
            'guardian-NIN.required' => 'Please Input Guardian\'s NIN !',
            'guardian-NIN.digits' => 'Invalid Guardian\'s NIN !',
            'fingerCode.required' => 'Please Input Customer\'s finger index !',
            'fingerData.required' => 'Please Input Customer\'s finger print !',
            'minor-relationship.required' => 'Please select Guardian Relationship to Minor !',

            /** New Minor Page2 */
            'firstName.required' => 'Please Input Minor\'s First Name !',
            'middleName.required' => 'Please Input Minor\'s Middle Name !',
            'lastName.required' => 'Please Input Minor\'s Last Name !',
            'dob.required' => 'Please Input Minor\'s Date of Birth !',
            'dob.regex' => 'Invalid Minor\'s Date of Birth !',
            'gender.required' => 'Please Input Minor\'s Gender !',
            'ID-select.required' => 'Please Select Minor\'s ID Type !',
            'ID-number.required' => 'Please Input Minor\'s ID Number !',
            'country.required' => 'Please Select Minor\'s Nationality !',
            'minor-ID-photo-file.required' => 'Please Upload Minor\'s ID Photo !',
            'minor-ID-photo-file.mimes' => 'Please Upload Minor\'s ID Photo Format in JPG or JPEG !',
            'minor-potrait-photo-file.required' => 'Please Upload Minor\'s Potrait Photo !',
            'minor-potrait-photo-file.mimes' => 'Please Upload Minor\'s Potrait Photo Format in JPG or JPEG !',

            /** Single Diplomat */
            'msisdn.required' => 'Please Input Phone Number !',
            'msisdn.regex' => 'Please Input valid Phone Number Format !',
            'firstName.required' => 'Please Input First Name !',
            'middleName.required' => 'Please Input Middle Name !',
            'lastName.required' => 'Please Input Last Name !',
            'dob.required' => 'Please Input Date of Birth !',

            'passport-number.required' => 'Please Input Passport Number !',
            'id-number.required' => 'Please Input ID Number !',
            'gender.required' => 'Please Select gender !',
            'institution.required' => 'Please Input Institution Name !',

            'country.required' => 'Please Select Country !',
            'front-id-file.required' => 'Please Upload scanned ID Front Side !',
            'back-id-file.required' => 'Please Upload scanned  ID Back Side !',
            'passport-file.required' => 'Please Upload scanned Passport !',

            'front-id-file.mimes' => 'Please upload correct document format, .PNG or .JPEG !',
            'back-id-file.mimes' => 'Please upload correct document format, .PNG or .JPEG !',
            'passport-file.mimes' => 'Please upload correct document format, .PNG or .JPEG !',

			'front-id-file.max' => 'Maximum Upload file of size of 200KB Exceeded !',
            'back-id-file.max' => 'Maximum Upload file of size of 200KB Exceeded !',
            'passport-file.max' => 'Maximum Upload file of size of 200KB Exceeded !',

            /** Bulk Diplomat Page1*/
            'institution.required' => 'Please Input Institution Name !',
            'adress.required' => 'Please Input Institution Address !',
            'region.required' => 'Please Select region !',
            'district.required' => 'Please Select district !',
            'ward.required' => 'Please Select ward !',
            'village.required' => 'Please Select street !',
            'post-code.required' => 'Please Input Post Code !',
            'post-code.numeric' => 'Please Input valid Post Code !',
            'msisdn-file.required' => 'Please Upload MSISDN file !',
            'msisdn-file.mimes' => 'Please upload correct document format, .CSV !',

            /** Bulk Diplomat Page2*/
            'msisdn.required' => 'Please Input Phone Number !',
            'msisdn.regex' => 'Please Input valid Phone Number Format !',
            'firstName.required' => 'Please Input First Name !',
            'middleName.required' => 'Please Input Middle Name !',
            'lastName.required' => 'Please Input Last Name !',
            'dob.required' => 'Please Input Date of Birth !',
            'expiry-date.required' => 'Please Input Expiry Date !',

            'passport-number.required' => 'Please Input Passport Number !',
            'id-number.required' => 'Please Input ID Number !',
            'gender.required' => 'Please Select gender !',
            'email.required' => 'Please Input Email Address !',
            'email.email' => 'Please Input valid Email Address !',

            'country.required' => 'Please Select Country !',
            'front-id-file.required' => 'Please Upload scanned ID Front Side !',
            'back-id-file.required' => 'Please Upload scanned  ID Back Side !',
            'passport-file.required' => 'Please Upload scanned Passport !',

            'front-id-file.mimes' => 'Please upload correct document format, .PNG or .JPEG !',
            'back-id-file.mimes' => 'Please upload correct document format, .PNG or .JPEG !',
            'passport-file.mimes' => 'Please upload correct document format, .PNG or .JPEG !',

            /** Total Mismatch*/
            'OTP.required' => 'Please Input OTP !',
            'OTP.digits' => 'Invalid OTP Format !',
        ];
    }
}
