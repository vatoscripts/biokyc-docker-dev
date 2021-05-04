<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class BulkRequest extends FormRequest
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
        // Check if Bulk Registration rules Page 1
        if ($this->is('bulk-registration-NIDA')) {
            return $this->bulkRegRules_page1();
        }
        // Check if Bulk Registration rules Page 2
        elseif ($this->is('bulk-registration-save')) {
            return $this->bulkRegRules_page2();
        }

        // Check if Bulk rules
        if ($this->is('api/one-sim/bulk/new-reg-post')) {
            return $this->NewBulkRegStartRules();
        }

        // Check if Bulk search rules
        if ($this->is('api/one-sim/bulk/new-reg-search')) {
            return $this->NewBulkRegSearchRules();
        }

        // Check if Bulk primary spoc rules
        if ($this->is('api/one-sim/bulk/primary-spoc')) {
            return $this->NewBulkRegPrimarySpocRules();
        }

        // Check if Bulk primary company rules
        if ($this->is('api/one-sim/bulk/primary-register')) {
            return $this->NewBulkRegPrimaryCompanyRules();
        }

        // Check Bulk secondary search rules
        if ($this->is('api/one-sim/bulk/company-search')) {
            return $this->bulkRegCompanySearchRules();
        }

        // Check if Bulk secondary spoc rules
        if ($this->is('api/one-sim/bulk/secondary-register')) {
            return $this->bulkRegSecondaryRules();
        }
    }


    private function NewBulkRegStartRules()
    {
        return [
            'companyName' => 'required',
        ];
    }

    private function bulkRegCompanySearchRules()
    {
        return [
            'selectedCompanyName' => 'required',
        ];
    }

    private function NewBulkRegSearchRules()
    {
        return [
            'companyName' => 'required',
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

    private function NewBulkRegPrimaryCompanyRules()
    {
        return [
            'msisdnFile' => 'required|mimes:csv,txt',
            'companyEmail' => 'required|email',
            'registrationCategory' => 'required',
            'machine2machine' => 'required',
            'companyRegDate' => 'required',
            'tinDate' =>  'required_if:registrationCategory,COMP_I,COMP_R',
            'brelaNumber' => 'required_if:registrationCategory,COMP_I',
            'brelaDate' => 'required_if:registrationCategory,COMP_I',
            'regCertNumber' => 'required_if:registrationCategory,COMP_R',
            'regCertDate' => 'required_if:registrationCategory,COMP_R',

            'TIN' => 'required_if:registrationCategory,COMP_I,COMP_R',
            'TINFile' => 'required_if:registrationCategory,COMP_I,COMP_R|mimes:jpeg,jpg,png|max:200',
            'businessLicenceFile' => 'required_if:registrationCategory,COMP_I,COMP_R|mimes:jpeg,jpg,png|max:200',
            'businessLicence' => 'required_if:registrationCategory,COMP_I,COMP_R',
            'brelaFile' => 'required_if:registrationCategory,COMP_I,COMP_R|mimes:jpeg,jpg,png|max:200',
            'spocAttachmentFile' => 'required_if:registrationCategory,INST|mimes:jpeg,jpg,png|max:200',
        ];
    }

    private function bulkRegSecondaryRules()
    {
        return [
            'msisdnFile' => 'required|mimes:csv,txt',
            'companyEmail' => 'required|email',
            'registrationCategory' => 'required',

            'machine2machine' => 'required',
            'companyRegDate' => 'required',
            'tinDate' =>  'required_if:registrationCategory,COMP,CEMP',
            'brelaNumber' => 'required_if:registrationCategory,COMP,CEMP',
            'brelaDate' => 'required_if:registrationCategory,COMP,CEMP',
            'regCertNumber' => 'required_if:registrationCategory,COMP,CEMP',
            'regCertDate' => 'required_if:registrationCategory,COMP,CEMP',

            'TIN' => 'required_if:registrationCategory,COMP,CEMP',
            'TINFile' => 'required_if:registrationCategory,COMP,CEMP|mimes:jpeg,jpg,png|max:200',
            'businessLicenceFile' => 'required_if:registrationCategory,COMP,CEMP|mimes:jpeg,jpg,png|max:200',
            'businessLicence' => 'required_if:registrationCategory,COMP,CEMP',
            'brelaFile' => 'required_if:registrationCategory,COMP,CEMP|mimes:jpeg,jpg,png|max:200',
            'spocAttachmentFile' => 'required_if:registrationCategory,INST|mimes:jpeg,jpg,png|max:200',
            'tcraReason' => 'required',
        ];
    }

    private function bulkRegRules_page1()
    {
        return [
            'spocEmail' => 'required|email',
            'spocMsisdn' => 'required|regex:/^\+?(255)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required',
            'region' => 'required',
            'district' => 'required',
            'ward' => 'required',
            'village' => 'required',
            //'expiry-date' => 'required',
        ];
    }

    private function bulkRegRules_page2()
    {
        return [
            'business-name' => 'required|string',
            'MSISDN-file' => 'required|mimes:csv,txt',
            'company-email' => 'required|email',
            'registrationCategory' => 'required',
            'machine2machine' => 'required',
            'TIN' => 'required_if:registrationCategory,COMP_I,COMP_R',
            'TIN-file' => 'required_if:registrationCategory,COMP_I,COMP_R|mimes:jpeg,jpg,png|max:200',
            'business-licence-file' => 'required_if:registrationCategory,COMP_I,COMP_R|mimes:jpeg,jpg,png|max:200',
            'business-licence' => 'required_if:registrationCategory,COMP_I,COMP_R',
            'BRELA-file' => 'required_if:registrationCategory,COMP_I,COMP_R|mimes:jpeg,jpg,png|max:200',
            'spoc-attachment-file' => 'required_if:registrationCategory,INST|mimes:jpeg,jpg,png|max:200',
        ];
    }

    public function messages()
    {
        return [
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
            'region.required' => 'Please Select region !',
            'district.required' => 'Please Select district !',
            'ward.required' => 'Please Select ward !',
            'village.required' => 'Please Select street !',
            'expiry-date.required' => 'Please Input Expiry Date !',

            /** BULK REGISTRATION Page2 **/
            'business-name.required' => 'Please Input Business or Company name !',
            'spoc-attachment-file.required_if' => 'Please Input Company\'s SPOC attachment file !',
            'MSISDN-file.mimes' => 'Company\'s phone numbers file must be in CSV format !',
            'MSISDN-file.required' => 'Please Input Company\'s phone numbers file !',
            'spoc-attachment-file.mimes' => 'Company\'s SPOC attachment must be in PNG, JPG or JPEG format !',
            'spoc-attachment-file.max' => 'Introduction Letter attachment Max file Size of 200KB Exceeded !',
            'company-email.required' => 'Please Input Company\'s E-mail Adress !',
            'company-email.email' => 'Invalid Company\'s E-mail Adress format !',

            'TIN.required_if' => 'Please Input Company TIN number !',
            'TIN.numeric' => 'Invalid Company TIN number !',
            'TIN-file.required_if' => 'Please Input Company\'s SPOC attachment file !',
            'TIN-file.mimes' => 'TIN file must be in PNG, JPG or JPEG format !',
            'TIN-file.max' => 'TIN file Max Size of 200KB Exceeded !',
            'business-licence.required_if' => 'Please Input Company\'s Business Licence number !',
            'business-licence.numeric' => 'Invalid Business Licence number !',
            'business-licence-file.required_if' => 'Please Input Business Licence file !',
            'business-licence-file.mimes' => 'Business Licence file must be in PNG, JPG or JPEG format !',
            'business-licence-file.max' => 'Business Licence file Max Size of 200KB  Exceeded !',
            'BRELA-file.required_if' => 'Please Input Certificate of Incorporation (BRELA) file !',
            'BRELA-file.mimes' => 'BRELA file must be in PNG, JPG or JPEG format !',
            'BRELA-file.max' => 'BRELA file Max  Size of 200KB Exceeded !',
            'registrationCategory.required' => 'Please Input Registration category !',
            'machine2machine.required' => 'Please select if is Machine-to-Machine registration !',

            /** BULK COMPANY SEARCH RULES */

            'Company.required' => 'Please select company !',
            'CompanyName.required' => 'Please select company !',
            'bulkTcraReason.required' => 'Please select reason for seeking approval of bulk secondary SIM numbers !',
            'selectedCompanyName.required' => 'Please select company !',

            /** NEW BULK MSISDN  */
            'companyName.required' => 'Please input company name !',

            /** NEW BULK SEARCH  */
            'company.required' => 'Please select company !',

            /** BULK REGISTRATION Page1 **/
            'spocEmail.required' => 'Please input SPOC\'s email adress !',
            'spocEmail.email' => 'Invalid SPOC\'s email adress !',
            'spocMsisdn.required' => 'Please input SPOC\'s phone number !',
            'spocMsisdn.email' => 'Invalid SPOC\'s phone number !',
            'NIN.required' => 'Please input NIDA ID !',
            'NIN.digits' => 'Invalid NIDA ID Format !',
            // 'fingerCode.required' => 'Please select SPOC\'s finger index !',
            // 'fingerData.required' => 'Please capture SPOC\'s finger print !',
            'phoneNumber.required' => 'Please input SPOC\'s phone number!',
            'phoneNumber.digits' => 'Invalid SPOC\'s phone number !',
            'phoneNumber.regex' => 'Invalid SPOC\'s phone number !',
            // 'region.required' => 'Please Select region !',
            // 'district.required' => 'Please Select district !',
            // 'ward.required' => 'Please Select ward !',
            'village.required' => 'Please select street !',
            'expiry-date.required' => 'Please input Expiry Date !',

            /** BULK REGISTRATION Page2 **/
            'spocAttachmentFile.required_if' => 'Please upload SPOC attachment file !',
            'msisdnFile.mimes' => 'Company\'s phone numbers file must be in CSV or TXT format !',
            'msisdnFile.required' => 'Please upload company\'s phone numbers file !',
            'spocAttachmentFile.mimes' => 'SPOC attachment must be in PNG, JPG or JPEG format !',
            'spocAttachmentFile.max' => 'Introduction letter attachment max file Size of 200KB exceeded !',
            'companyEmail.required' => 'Please input company\'s e-mail adress !',
            'companyEmail.email' => 'Invalid company\'s e-mail adress format !',

            'TIN.required_if' => 'Please input company TIN number !',
            'TIN.numeric' => 'Invalid company TIN number !',
            'TINFile.required_if' => 'Please upload TIN file !',
            'TINFile.mimes' => 'TIN file must be in PNG, JPG or JPEG format !',
            'TINFile.max' => 'TIN file max size of 200KB exceeded !',
            'businessLicence.required_if' => 'Please input business licence number !',
            'businessLicence.numeric' => 'Invalid business licence number !',
            'businessLicenceFile.required_if' => 'Please upload business licence file !',
            'businessLicenceFile.mimes' => 'Business licence file must be in PNG, JPG or JPEG format !',
            'businessLicenceFile.max' => 'Business licence file max Size of 200KB  exceeded !',
            'brelaFile.required_if' => 'Please upload Certificate of Incorporation (BRELA) file !',
            'brelaFile.mimes' => 'BRELA file must be in PNG, JPG or JPEG format !',
            'brelaFile.max' => 'Certificate of Incorporation (BRELA) file Max  Size of 200KB exceeded !',
            'registrationCategory.required' => 'Please select registration category !',
            'machine2machine.required' => 'Please select if  Machine-to-machine registration !',
            'companyRegDate.required' => 'Please select company registration date !',
            'tinDate.required_if' =>  'Please select TIN registration date !',
            'brelaNumber.required_if' => 'Please input Incorporation(BRELA) number !',
            'brelaDate.required_if' => 'Please select Incorporation(BRELA) registration date !',
            'regCertNumber.required_if' => 'Please input Certificate of Registration  number !',
            'regCertDate.required_if' => 'Please select Certificate of Registration date !',

        ];
    }
}
