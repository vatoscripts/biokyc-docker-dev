<?php

namespace App\Http\Controllers\API\Registration;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\BulkRequest;
use Illuminate\Support\Facades\Log;
use Session;
use Route;

class BulkRegistrationController extends GuzzleController
{
    const ERROR_OCCURED = 'Sorry, An error has coccured . Try again !';
    const EMPTY_BLANK_LINE = 'Empty line or Blank msisdn Found on CSV file !';
    const INCORRECT_MSISDN = 'Incorrect Msisdn Found on CSV file : ';

    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_REGISTRAL,ROLE_SPECIAL_REGISTRAL,ROLE_MAKER']);
        $this->middleware(['role:ROLE_SPECIAL_REGISTRAL'])->only(['bulkSecondaryRegistration', 'bulkPrimaryRegistration', 'bulkSpocRegistration', 'diplomatCheck', 'diplomatRegisterPrimary', 'diplomatRegisterSecondary']);
    }

    public function postBulkRegistrationStart(BulkRequest $request)
    {
        $body = [
            'Companyname' => $request->companyName
        ];

        $url = 'GetCompanyNames';

        return $this->postRequest($url, $body);
    }

    public function postBulkRegistrationSearch(BulkRequest $request)
    {
        if (str_word_count($request->companyName) < 2) {
            return  response()->json(['message' => 'Company name should contain atleast 2 words e.g ' . $request->companyName . ' LIMITED'], 400);
        }

        $data =  $this->postBulkRegistrationStart($request);

        foreach ($data as $value) {
            if (strcasecmp($value['CompanyName'], $request->companyName) == 0) {
                return  response()->json(['message' => 'Company name already exists, please select from the provided list !'], 400);
            }
        }

        $request->session()->put('companyName', $request->companyName);

        return response()->json(null, 200);
    }

    public function bulkRegistrationSecondarySearch(BulkRequest $request)
    {
        $request->session()->put('companyName', $request->selectedCompanyName);

        return response()->json(null, 200);
    }

    public function bulkSpocRegistration(BulkRequest $request)
    {
        $spoc = [
            'email' => $request->spocEmail,
            'msisdn' => $request->spocMsisdn,
            'village' => $request->village,
        ];

        $body = [
            'NIN' => $request->NIN,
            'FingerCode' => $request->fingerCode,
            'FingerData' => $request->fingerData,
        ];

        $url = 'NIDA';

        $data = $this->postRequest($url, $body);

        $dataNew = $data;
        unset($body['FingerData']);
        unset($dataNew['PHOTO']);
        unset($dataNew['SIGNATURE']);

        Log::channel('Bulk-Reg-nida')->debug(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $dataNew]);

        if ($data['ErrorCode'] == 0) {
            Session::put(['NIDAdata' => $data, 'spoc' => $spoc]);

            return response()
                ->json([
                    'message' => null,
                    'status' => $data['ErrorCode']
                ], 200);
        } elseif ($data['ErrorCode'] == '01') {
            return response()
                ->json([
                    'message' => 'Customer Biometric verification failed',
                    'status' => $data['ErrorCode']
                ], 400);
        } elseif ($data['ErrorCode'] == '132') {

            return response()
                ->json([
                    'message' => 'Customer NIN not found',
                    'status' => $data['ErrorCode']
                ], 400);
        } elseif ($data['ErrorCode'] == '141') {
            return response()
                ->json([
                    'message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !',
                    'status' => $data['ErrorCode']
                ], 400);
        } elseif ($data['ErrorCode'] == '-10') {
            return response()
                ->json([
                    'message' => 'Connection timeout from NIDA .Please try again !',
                    'status' => $data['ErrorCode']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => self::ERROR_OCCURED,
                    'status' => $data['ErrorCode']
                ], 400);
        }
    }

    public function bulkPrimaryRegistration(BulkRequest $request)
    {
        // return response()->json($request->all(), 200);

        $NIDA = $request->session()->get('NIDAdata');
        $SPOC = $request->session()->get('spoc');

        $MSISDNfile = file_get_contents($request->file('msisdnFile'));
        $MSISDNFilebase64 = base64_encode($MSISDNfile);

        foreach (explode("\n", $MSISDNfile) as $key => $line) {
            $array[$key] =  $line;
        }

        if (count($array) > 50) {
            return  response()->json(['message' => 'Exceeded maximum 200 Msisdn in CSV file !'], 400);
        }

        $request->machine2machine == 'Y' ?  $this->checkMsidnNewRange($array) :
            $this->checkMsidnOldRange($array);

        if ($request->registrationCategory == 'COMP_I') {
            $tinDate = date('Y-m-d', strtotime(substr($request->tinDate, 0, strpos($request->tinDate, '('))));
            $brelaDate = date('Y-m-d', strtotime(substr($request->brelaDate, 0, strpos($request->brelaDate, '('))));
            $companyRegDate = date('Y-m-d', strtotime(substr($request->companyRegDate, 0, strpos($request->companyRegDate, '('))));
            $cat = "COMP";
            $regCertDate = null;
        } elseif ($request->registrationCategory == 'COMP_R') {
            $tinDate = date('Y-m-d', strtotime(substr($request->tinDate, 0, strpos($request->tinDate, '('))));
            $regCertDate = date('Y-m-d', strtotime(substr($request->regCertDate, 0, strpos($request->regCertDate, '('))));
            $companyRegDate = date('Y-m-d', strtotime(substr($request->companyRegDate, 0, strpos($request->companyRegDate, '('))));
            $cat = "COMP";
            $brelaDate = null;
        } else {
            $tinDate = null;
            $regCertDate = null;
            $brelaDate = null;
            $companyRegDate = null;
            $cat = $request->registrationCategory;
        }

        if ($request->file('spocAttachmentFile')) {
            $SPOCFile = file_get_contents($request->file('spocAttachmentFile'));
            $SPOCFilebase64 = base64_encode($SPOCFile);
        } else {
            $SPOCFilebase64 = null;
        }

        if ($request->file('TINFile')) {
            $TINFile = file_get_contents($request->file('TINFile'));
            $TINFilebase64 = base64_encode($TINFile);
        } else {
            $TINFilebase64 = null;
        }

        if ($request->file('businessLicenceFile')) {
            $LicenceFile = file_get_contents($request->file('businessLicenceFile'));
            $LicenceFilebase64 = base64_encode($LicenceFile);
        } else {
            $LicenceFilebase64 = null;
        }

        if ($request->file('brelaFile')) {
            $BRELAFile = file_get_contents($request->file('brelaFile'));
            $BRELAFilebase64 = base64_encode($BRELAFile);
        } else {
            $BRELAFilebase64 = null;
        }

        $body = [
            'CompanyName' => $request->session()->get('companyName'),
            'CompanyEmail' => $request->companyEmail,
            'Category' => $cat,
            'SpocAttachment' => $SPOCFilebase64,
            'MsisdnList' => $MSISDNFilebase64,
            'UserID' => $this->user['UserID'],
            'MARITALSTATUS' => $NIDA['MARITALSTATUS'],
            'PHONENUMBER' => $NIDA['PHONENUMBER'],
            'NATIONALITY' => $NIDA['NATIONALITY'],
            'BIRTHCERTIFICATENO' => $NIDA['BIRTHCERTIFICATENO'],
            'BIRTHWARD' => $NIDA['BIRTHWARD'],
            'BIRTHDISTRICT' => $NIDA['BIRTHDISTRICT'],
            'BIRTHREGION' => $NIDA['BIRTHREGION'],
            'BIRTHCOUNTRY' => $NIDA['BIRTHREGION'],
            'RESIDENTPOSTCODE' => $NIDA['RESIDENTPOSTCODE'],
            'RESIDENTPOSTALADDRESS' => $NIDA['RESIDENTPOSTALADDRESS'],
            'RESIDENTSTREET' => $NIDA['RESIDENTSTREET'],
            'RESIDENTHOUSENO' => $NIDA['RESIDENTHOUSENO'],
            'RESIDENTVILLAGE' => $NIDA['RESIDENTVILLAGE'],
            'RESIDENTWARD' => $NIDA['RESIDENTWARD'],
            'RESIDENTDISTRICT' => $NIDA['RESIDENTDISTRICT'],
            'RESIDENTREGION' => $NIDA['RESIDENTREGION'],
            'DATEOFBIRTH' => $NIDA['DATEOFBIRTH'],
            'SEX' => $NIDA['SEX'],
            'OTHERNAMES' => $NIDA['OTHERNAMES'],
            'SURNAME' => $NIDA['SURNAME'],
            'MIDDLENAME' => $NIDA['MIDDLENAME'],

            'FIRSTNAME' => $NIDA['FIRSTNAME'],
            'NIN' => $NIDA['NIN'],
            'ID' => $NIDA['ID'],
            'PHOTO' => $NIDA['PHOTO'],
            'Time' => $NIDA['Time'],
            'SIGNATURE' => $NIDA['SIGNATURE'],

            'Tin' => $request->input('registrationCategory') == 'INST' ? null : $request->TIN,
            'TinDoc' => $TINFilebase64,
            'BusinessLicenseNo' => $request->input('registrationCategory') == 'INST' ? null : $request->businessLicence,
            'BusinessDoc' => $LicenceFilebase64,
            'SpocPhone' => $SPOC['msisdn'],
            'SpocEmail' => $SPOC['email'],
            'BrelaDoc' => $BRELAFilebase64,

            'VillageID' => $SPOC['village'],

            'TinRegDate' => $tinDate,
            'CertOfIncorporationDate' => $brelaDate,
            'CertOfRegDate' => $regCertDate,
            'companyRegDate' => $companyRegDate,
            'CertOfIncorporationNO' => $request->input('registrationCategory') == 'COMP_I' ?  $request->brelaNumber : null,
            'CertOfRegNO' => $request->input('registrationCategory') == 'COMP_R' ? $request->regCertNumber : null,
        ];

        $url = 'CorporatePrimary';

        $data = $this->postRequest($url, $body);

        unset($body['SIGNATURE']);
        unset($body['TinDoc']);
        unset($body['BusinessDoc']);
        unset($body['BrelaDoc']);
        unset($body['PHOTO']);
        unset($body['SpocAttachment']);
        unset($body['MsisdnList']);

        Log::channel('Bulk-Reg-primary')->debug(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            $request->session()->forget('NIDAdata');
            $request->session()->forget('spoc');
            $request->session()->forget('companyName');

            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 200);
        } elseif ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => self::ERROR_OCCURED,
                ], 400);
        }
    }

    public function bulkSecondaryRegistration(BulkRequest $request)
    {
        $NIDA = $request->session()->get('NIDAdata');
        $SPOC = $request->session()->get('spoc');

        $MSISDNfile = file_get_contents($request->file('msisdnFile'));
        $MSISDNFilebase64 = base64_encode($MSISDNfile);

        foreach (explode("\n", $MSISDNfile) as $key => $line) {
            $array[$key] =  $line;
        }

        $request->machine2machine == 'Y' ?  $this->checkMsidnNewRange($array) :
            $this->checkMsidnOldRange($array);

        if ($request->registrationCategory == 'COMP_I') {
            $tinDate = date('Y-m-d', strtotime(substr($request->tinDate, 0, strpos($request->tinDate, '('))));
            $brelaDate = date('Y-m-d', strtotime(substr($request->brelaDate, 0, strpos($request->brelaDate, '('))));
            $companyRegDate = date('Y-m-d', strtotime(substr($request->companyRegDate, 0, strpos($request->companyRegDate, '('))));
            $cat = "COMP";
            $regCertDate = null;
        } elseif ($request->registrationCategory == 'COMP_R') {
            $tinDate = date('Y-m-d', strtotime(substr($request->tinDate, 0, strpos($request->tinDate, '('))));
            $regCertDate = date('Y-m-d', strtotime(substr($request->regCertDate, 0, strpos($request->regCertDate, '('))));
            $companyRegDate = date('Y-m-d', strtotime(substr($request->companyRegDate, 0, strpos($request->companyRegDate, '('))));
            $cat = "COMP";
            $brelaDate = null;
        } else {
            $tinDate = null;
            $regCertDate = null;
            $brelaDate = null;
            $companyRegDate = null;
            $cat = $request->registrationCategory;
        }

        if ($request->file('spocAttachmentFile')) {
            $SPOCFile = file_get_contents($request->file('spocAttachmentFile'));
            $SPOCFilebase64 = base64_encode($SPOCFile);
        } else {
            $SPOCFilebase64 = null;
        }

        if ($request->file('TINFile')) {
            $TINFile = file_get_contents($request->file('TINFile'));
            $TINFilebase64 = base64_encode($TINFile);
        } else {
            $TINFilebase64 = null;
        }

        if ($request->file('businessLicenceFile')) {
            $LicenceFile = file_get_contents($request->file('businessLicenceFile'));
            $LicenceFilebase64 = base64_encode($LicenceFile);
        } else {
            $LicenceFilebase64 = null;
        }

        if ($request->file('brelaFile')) {
            $BRELAFile = file_get_contents($request->file('brelaFile'));
            $BRELAFilebase64 = base64_encode($BRELAFile);
        } else {
            $BRELAFilebase64 = null;
        }

        $body = [
            'CompanyName' => $request->session()->get('companyName'),
            'CompanyEmail' => $request->companyEmail,
            'Category' => $cat,
            'SpocAttachment' => $SPOCFilebase64,
            'MsisdnList' => $MSISDNFilebase64,
            'UserID' => $this->user['UserID'],
            'MARITALSTATUS' => $NIDA['MARITALSTATUS'],
            'PHONENUMBER' => $NIDA['PHONENUMBER'],
            'NATIONALITY' => $NIDA['NATIONALITY'],
            'BIRTHCERTIFICATENO' => $NIDA['BIRTHCERTIFICATENO'],
            'BIRTHWARD' => $NIDA['BIRTHWARD'],
            'BIRTHDISTRICT' => $NIDA['BIRTHDISTRICT'],
            'BIRTHREGION' => $NIDA['BIRTHREGION'],
            'BIRTHCOUNTRY' => $NIDA['BIRTHREGION'],
            'RESIDENTPOSTCODE' => $NIDA['RESIDENTPOSTCODE'],
            'RESIDENTPOSTALADDRESS' => $NIDA['RESIDENTPOSTALADDRESS'],
            'RESIDENTSTREET' => $NIDA['RESIDENTSTREET'],
            'RESIDENTHOUSENO' => $NIDA['RESIDENTHOUSENO'],
            'RESIDENTVILLAGE' => $NIDA['RESIDENTVILLAGE'],
            'RESIDENTWARD' => $NIDA['RESIDENTWARD'],
            'RESIDENTDISTRICT' => $NIDA['RESIDENTDISTRICT'],
            'RESIDENTREGION' => $NIDA['RESIDENTREGION'],
            'DATEOFBIRTH' => $NIDA['DATEOFBIRTH'],
            'SEX' => $NIDA['SEX'],
            'OTHERNAMES' => $NIDA['OTHERNAMES'],
            'SURNAME' => $NIDA['SURNAME'],
            'MIDDLENAME' => $NIDA['MIDDLENAME'],

            'FIRSTNAME' => $NIDA['FIRSTNAME'],
            'NIN' => $NIDA['NIN'],
            'ID' => $NIDA['ID'],
            'PHOTO' => $NIDA['PHOTO'],
            'Time' => $NIDA['Time'],
            'SIGNATURE' => $NIDA['SIGNATURE'],

            'Tin' => $request->TIN,
            'TinDoc' => $TINFilebase64,
            'BusinessLicenseNo' => $request->businessLicence,
            'BusinessDoc' => $LicenceFilebase64,
            'SpocPhone' => $SPOC['msisdn'],
            'SpocEmail' => $SPOC['email'],
            'BrelaDoc' => $BRELAFilebase64,

            'VillageID' => $SPOC['village'],
            'ReasonCode' => $request->tcraReason,

            'TinRegDate' => $tinDate,
            'CertOfIncorporationDate' => $brelaDate,
            'CertOfRegDate' => $regCertDate,
            'companyRegDate' => $companyRegDate,
            'CertOfIncorporationNO' => $request->input('registrationCategory') == 'COMP_I' ? $request->brelaNumber : null,
            'CertOfRegNO' => $request->input('registrationCategory') == 'COMP_R' ? $request->regCertNumber : null,
        ];

        $url = 'CorporateSecondary';

        $data = $this->postRequest($url, $body);

        unset($body['SIGNATURE']);
        unset($body['TinDoc']);
        unset($body['BusinessDoc']);
        unset($body['BrelaDoc']);
        unset($body['PHOTO']);
        unset($body['SpocAttachment']);
        unset($body['MsisdnList']);

        Log::channel('Bulk-Reg-secondary')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RequestStatusCode'] == 0 && $data['responseCode'] == 150) {
            $request->session()->forget('NIDAdata');
            $request->session()->forget('spoc');
            $request->session()->forget('companyName');

            return response()->json(['message' => 'Request submitted susccessfully. Please check your email for registration status !'], 200);
        } elseif ($data['responseCode'] == 151) {
            return response()->json([
                'message' => 'Customer NIN is blacklisted by TCRA !',
                'status' => $data['responseCode']
            ], 400);
        } elseif ($data['responseCode'] == 152) {
            return response()->json([
                'message' => 'Agent NIN is blacklisted by TCRA !',
                'status' => $data['responseCode']
            ], 400);
        } elseif ($data['responseCode'] == 153) {
            return response()->json([
                'message' => 'Customer has reached maximum SIM cards !',
                'status' => $data['responseCode']
            ], 400);
        } elseif ($data['responseCode'] == 154) {
            return response()->json([
                'message' => 'Customer reason not accepted by TCRA. Please choose another !',
                'status' => $data['responseCode']
            ], 400);
        } elseif ($data['responseCode'] == 156) {
            return response()->json([
                'message' => 'Duplicate customer msisdn(s) from TCRA !',
                'status' => $data['responseCode']
            ], 400);
        } else {
            return response()
                ->json([
                    'message' => self::ERROR_OCCURED,
                ], 400);
        }
    }

    public function bulkDeclaration(BulkRequest $request)
    {
        $MSISDNfile = file_get_contents($request->file('msisdnFile'));
        $MSISDNFilebase64 = base64_encode($MSISDNfile);

        foreach (explode("\n", $MSISDNfile) as $key => $line) {
            $array[$key] =  $line;
        }

        $this->checkMsidnOldRange($array);

        $body = [
            'MsisdnList' => $MSISDNFilebase64,
            'SPOCNIN' => $request->NIN,
            'reasonCode' => $request->bulkTcraReason,
            'CompanyName' => $request->session()->get('companyName'),
            'SPOCMSISDN' => $request->spocMsisdn,
            'MsisdnStatus' => 'SECONDARY',
            'UserID' => $this->user['UserID']
        ];

        $url = 'BulkDeclaration';

        $data = $this->postRequest($url, $body);

        Log::channel('Bulk-declaration')->debug(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RequestStatusCode'] === 0) {
            return response()->json(['message' => 'Successful Bulk Declaration !'], 200);
        }
        if ($data['RequestStatusCode'] == 117) {
            return response()->json(['message' => 'SPOC does not belong to this company !'], 400);
        } elseif ($data['RequestStatusCode'] == 97) {
            return response()->json(['message' => 'Unauthorised user !'], 400);
        } elseif ($data['RequestStatusCode'] == 99) {
            return response()->json(['message' => 'An error has occured !'], 400);
        } elseif ($data['responseCode'] == 151) {
            return response()->json(['message' => 'Customer NIN is blacklisted by TCRA !'], 400);
        } elseif ($data['responseCode'] == 152) {
            return response()->json(['message' => 'Agent NIN is blacklisted by TCRA !'], 400);
        } elseif ($data['responseCode'] == 153) {
            return response()->json(['message' => 'Customer has reached maximum SIM cards !'], 400);
        } elseif ($data['responseCode'] == 154) {
            return response()->json(['message' => 'Customer reason not accepted by TCRA. Please choose another !'], 400);
        } elseif ($data['responseCode'] == 156) {
            return response()->json(['message' => 'Duplicate customer msisdn from TCRA !'], 400);
        } else {
            return response()->json(['message' => self::ERROR_OCCURED], 400);
        }

        /**
         * 0 - Success
         * 117 - SPOC does not belong to this company
         * responseCOde corresponds to TCRA codes
         * 96 - TCRA
         * 97 -  Unauthorized user
         * 99 - General error
         */
    }

    private function checkMsidnOldRange($array)
    {
        foreach ($array as $el) {
            if (!preg_match("/^\+?(255)-?([0-9]{3})-?([0-9]{6})$/", (int) $el)) {
                if ((int) $el == 0) {
                    return  response()->json(['message' => self::EMPTY_BLANK_LINE], 400);
                }

                return  response()->json(['message' => self::INCORRECT_MSISDN . (int) $el], 400);
            }
        }
    }

    private function checkMsidnNewRange($array)
    {
        foreach ($array as $el) {
            if (!preg_match("/^(25530003)-?([0-9]{7})$/", (int) $el)) {
                if ((int) $el == 0) {
                    return  response()->json(['message' => self::EMPTY_BLANK_LINE], 400);
                }

                return  response()->json(['message' => self::INCORRECT_MSISDN . (int) $el], 400);
            }
        }
    }
}
