<?php

namespace App\Http\Requests;

use Carbon\Carbon as CarbonCarbon;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Carbon;

class RegistrationRequest extends FormRequest
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
        if ($this->is('one-sim/new-reg-post')) {
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

        // // Check if New Diplomat rules
        // if ($this->is('one-sim/diplomat/new-reg-post') ) {
        //     return $this->NewDiplomatRegStartRules();
        // }

        // Check if Single Diplomat Primary rules
        if ($this->is('api/diplomat/register-primary')) {
            return $this->diplomatPrimaryRules();
        }

        // Check if Single Diplomat Secondary rules
        if ($this->is('api/diplomat/register-secondary')) {
            return $this->diplomatSecondaryRules();
        }

        // Check if New Visitor rules
        if ($this->is('api/visitor/check-msisdn')) {
            return $this->NewVisitorRegStartRules();
        }

        // Check if Visitor Primary rules
        if ($this->is('api/visitor/register-primary')) {
            return $this->NewVisitorRegPrimaryRules();
        }

        // Check if Visitor Secondary rules
        if ($this->is('api/visitor/register-secondary')) {
            return $this->NewVisitorRegSecondaryRules();
        }

        // Check if Minor start rules
        if ($this->is('api/one-sim/minor/check-msisdn')) {
            return $this->MinorCheckMsisdnRules();
        }

        // Check if Minor register rules
        if ($this->is('api/one-sim/minor/register')) {
            return $this->MinorRegisterRules();
        }

        // Check if Set Primary start rules
        if ($this->is('api/primary/check-msisdn') || $this->is('api/secondary/check-msisdn')) {
            return $this->setPrimaryStartRules();
        }

        // Check if Set Primary rules
        if ($this->is('api/primary/set-msisdn')) {
            return $this->setPrimaryRules();
        }

        // Check if Set Secondary rules
        if ($this->is('api/secondary/set-msisdn')) {
            return $this->setSecondaryRules();
        }

        // Check diplomat start rules
        if ($this->is('api/diplomat/check-msisdn')) {
            return $this->diplomatStartRules();
        }

        // Check NIDA start rules
        if ($this->is('api/nida/check-msisdn')) {
            return $this->NidaStartRules();
        }

        // Check NIDA start rules
        if ($this->is('api/nida/register-primary')) {
            return $this->NidaPrimaryRules();
        }

        // Check NIDA start rules
        if ($this->is('api/nida/register-secondary')) {
            return $this->NidaSecondaryRules();
        }

        // Check Bulk Declaration rules
        if ($this->is('api/one-sim/bulk/declaration')) {
            return $this->BulkDeclarationRules();
        }

        // Check Dereg NIDA rules
        if ($this->is('api/dereg/nida')) {
            return $this->DeregNIDAnRules();
        }

        // Check Dereg Msisdn rules
        if ($this->is('api/dereg/msisdn')) {
            return $this->DeregMsisdnRules();
        }

        // Check Dereg Code rules
        if ($this->is('api/dereg/code')) {
            return $this->DeregCodeRules();
        }
    }

    private function DeregNIDAnRules()
    {
        return [
            'msisdn' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ];
    }

    private function DeregMsisdnRules()
    {
        return [
            'deregMsisdn' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/',
        ];
    }

    private function DeregCodeRules()
    {
        return [
            'codeNumber' => 'required|digits:6',
            'deregReason' => 'required'
        ];
    }

    private function BulkDeclarationRules()
    {
        return [
            'spocMsisdn' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required | digits:20',
            'bulkTcraReason' => 'required',
            'msisdnFile' => 'required|mimes:csv,txt',
        ];
    }

    private function NidaStartRules()
    {
        return [
            'msisdn' => 'required|regex:/^(0)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required | digits:20',
        ];
    }

    private function NidaPrimaryRules()
    {
        return [
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ];
    }

    private function NidaSecondaryRules()
    {
        return [
            'fingerCode' => 'required',
            'fingerData' => 'required',
            'tcraReason' => 'required'
        ];
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

    private function diplomatStartRules()
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

    private function diplomatPrimaryRules()
    {
        return [
            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',

            'idNumber' => 'required',
            'gender' => 'required',
            'institution' => 'required',
            'dob' => 'required',

            'country' => 'required',
            'frontIDFile' => 'required|max:200|mimes:jpeg,jpg,png',
            'backIDFile' => 'required|max:200|mimes:jpeg,jpg,png',
            'passportFile' => 'required|max:200|mimes:jpeg,jpg,png'
        ];
    }

    private function diplomatSecondaryRules()
    {
        return [
            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',

            'idNumber' => 'required',
            'gender' => 'required',
            'institution' => 'required',
            'dob' => 'required',

            'country' => 'required',
            'frontIDFile' => 'required|max:200|mimes:jpeg,jpg,png',
            'backIDFile' => 'required|max:200|mimes:jpeg,jpg,png',
            'passportFile' => 'required|max:200|mimes:jpeg,jpg,png',

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

    private function MinorCheckMsisdnRules()
    {
        return [
            'msisdn' => 'required|regex:/^(0)-?([0-9]{3})-?([0-9]{6})$/',
        ];
    }

    private function MinorRegisterRules()
    {
        $dt = new CarbonCarbon();
        $before = $dt->subYears(13)->format('Y-m-d');

        return [
            'parentMsisdn' => 'required |regex:/^(0)-?([0-9]{3})-?([0-9]{6})$/',
            //'minor-relationship' => 'required',
            'parentNIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required',

            'firstName' => 'required',
            'middleName' => 'required',
            'lastName' => 'required',
            'minorDOB' => 'required|before:' . $before,
            //'minorDOB' => 'required|after_or_equal:-18 years',
            // 'minorDOB' => 'required|regex:/\+?([0-31]{2})-?([0-12]{2})-?([1900-2020]{4})$/',

            'minorGender' => 'required',
            //'ID-select' => 'required',
            'idNumber' => 'required',
            //'minorNationality' => 'required',

            'IDFile' => 'required|mimes:jpeg,jpg,png|max:200',
            'potraitFile' => 'required|mimes:jpeg,jpg,png|max:200',
        ];
    }

    private function setPrimaryStartRules()
    {
        return [
            'idType' => 'required',
            //'NIN' => 'required_if:idType,==,N| digits:20',
            'idNumber' => 'required',
        ];
    }

    private function setPrimaryRules()
    {
        return [
            'msisdnPrimary' => 'required',
        ];
    }

    private function setSecondaryRules()
    {
        return [
            'msisdnSecondary' => 'required',
            'tcraReason' => 'required',
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
            'fingerCode.required' => 'Please select customer\'s finger index !',
            'fingerData.required' => 'Please capture customer\'s finger print !',

            /** NEW SECONDARY MSISDN **/
            'fingerCode.required' => 'Please select Customer\'s finger index !',
            'fingerData.required' => 'Please capture Customer\'s finger print !',
            'tcraReason.required' => 'Please select TCRA reason !',

            /** START DIPLOMAT PAGE **/
            'msisdn.required' => 'Please input customer\'s phone number !',
            'msisdn.regex' => 'Invalid customer\'s phone number !',
            'passportNumber.required' => 'Please input customer\'s passport number !',

            /** Single Diplomat */
            'firstName.required' => 'Please input first name !',
            'middleName.required' => 'Please input middle name !',
            'lastName.required' => 'Please input last name !',
            'dob.required' => 'Please input Date of birth !',

            'gender.required' => 'Please select gender !',
            'institution.required' => 'Please input Institution name !',

            'country.required' => 'Please select country !',
            'frontIDFile.required' => 'Please upload scanned diplomat ID front side !',
            'backIDFile.required' => 'Please upload scanned diplomat ID back side !',
            'passportFile.required' => 'Please upload scanned Passport !',

            'frontIDFile.mimes' => 'Please upload correct diplomat ID document format, .PNG or .JPEG !',
            'backIDFile.mimes' => 'Please upload correct diplomat ID document format, .PNG or .JPEG !',
            'passportFile.mimes' => 'Please upload correct document format, .PNG or .JPEG !',

            'frontIDFile.max' => 'Maximum upload file of size of 200KB exceeded !',
            'backIDFile.max' => 'Maximum upload file of size of 200KB exceeded !',
            'passportFile.max' => 'Maximum upload file of size of 200KB exceeded !',

            /** NEW VISITOR MSISDN  */
            'issuingCountry.required' => 'Please select issuing country code !',
            'tcraReason.required' => 'Please select TCRA reason !',

            /** MINOR REGISTRATION */
            'parentMsisdn.required' => 'Please input parent\'s phone number!',
            'parentMsisdn.regex' => 'Invalid parent\'s phone number !',
            'parentNIN.required' => 'Please input parent\'s NIN !',
            'parentNIN.digits' => 'Invalid parent\'s NIN !',
            'minor-relationship.required' => 'Please select parent Relationship to Minor !',

            // 'firstName.required' => 'Please input minor\'s first name !',
            // 'middleName.required' => 'Please input minor\'s middle name !',
            // 'lastName.required' => 'Please input minor\'s last name !',
            'minorDOB.required' => 'Please select minor\'s Date of Birth !',
            'minorDOB.before_or_equal' => 'Minor\'s age should not exceed 18 years !',
            'minorGender.required' => 'Please input minor\'s gender !',
            'ID-select.required' => 'Please select Minor\'s ID Type !',
            'idNumber.required' => 'Please input minor\'s ID number !',
            'minorNationality.required' => 'Please select minor\'s nationality !',
            'IDFile.required' => 'Please upload minor\'s ID Photo !',
            'IDFile.mimes' => 'Please upload minor\'s ID Photo format in JPG or JPEG !',
            'potraitFile.required' => 'Please upload minor\'s potrait photo !',
            'potraitFile.mimes' => 'Please upload minor\'s potrait photo format in JPG or JPEG !',
            'IDFile.max' => 'Minor\'s ID Certificate/Passport max size of 200KB exceeded !',
            'potraitFile.max' => 'Minor\'s potrait photo max size of 200KB exceeded !',

            /** START SET PRIMARY */
            'NIN.required_if' => 'Please input customer NIN !',
            'idNumber.required_if' => 'Please input customer NIN !',
            'idNumber.required' => 'Please input customer ID number !',
            'NIN.digits' => 'Invalid customer\'s NIN ! !',
            'idType.required' => 'Please select customer\'s ID category !',

            /** SET PRIMARY */
            'msisdnPrimary.required' => 'Please select one msisdn to set as primary !',

            /** SET SECONDARY */
            'tcraReason.required' => 'Please select reason for seeking approval of secondary SIM number !',
            'msisdnSecondary.required' => 'Please select customer MSISDN to set as secondary SIM number !',

            /** De-Reg  */
            'deregMsisdn.required' => 'Please select customer Msisdn to De-register !',
            'codeNumber.required' => 'Please input De-registration code !',
            'codeNumber.digits' => 'Invalid De-registration code !',
            'deregReason.required' => 'Please select De-registration reason !'
        ];
    }
}
