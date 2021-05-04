<?php

namespace App\Http\Controllers\KYC;

use Illuminate\Http\Request;
use Session;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\BulkRequest;
use Illuminate\Support\Facades\Log;
use Route;
use File;
use Input;

class BulkRegController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_SPECIAL_REGISTRAL']);
    }

    public function showBulkRegistrationForm()
    {
        session::forget('NIDAdata');
        session::forget('spoc');
        return view('register.bulk-reg.bulk-registration')->with('regions', $this->getRegions());
    }

    public function processBulkRegistration_page1(BulkRequest $request)
    {
        $spoc = [
            'email' => $request->spocEmail,
            'msisdn' => $request->spocMsisdn,
            'category' => $request->registrationCategory,
            'village' => $request->get('village'),
        ];

        $body = [
            'NIN' => $request->get('NIN'),
            'FingerCode' => $request->get('fingerCode'),
            'FingerData' => $request->get('fingerData'),
        ];

        $url = 'NIDA';

        $data = $this->postRequest($url, $body);


        $dataNew = $data;
        unset( $body['FingerData']);
        unset( $dataNew['PHOTO']);
        unset( $dataNew['SIGNATURE']);

        Log::channel('Bulk-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $dataNew]);

        if ($data['ErrorCode'] == 0) {
            session::put(['NIDAdata' => $data, 'spoc' => $spoc]);
            return response()
                ->json([
                    'message' => $spoc,
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
                    'message' => $data['ErrorMessage'],
                    'status' => $data['ErrorCode']
                ], 400);
        }
    }

    public function processBulkRegistration_page2(BulkRequest $request)
    {
        $NIDA = $request->session()->get('NIDAdata');
        $SPOC = $request->session()->get('spoc');

        $MSISDNfile = file_get_contents($request->file('MSISDN-file'));
        $MSISDNFilebase64 = base64_encode($MSISDNfile);

        if(str_word_count($request->input('business-name')) < 2)
        {
            return  response()->json(['message' => 'Please check company name should contain atleast 2 words e.g ' .$request->input('business-name'). ' LIMITED'], 400);
        }

        foreach (explode("\n", $MSISDNfile) as $key=>$line){
            $array[$key] =  $line;
        }

        if($request->machine2machine == 'Y')
        {
            if($request->registrationCategory == 'CEMP') {
                return  response()->json(['message' => 'Registration category can not be Machine SIM Card !'], 400);
            }
            foreach($array as $el)
            {
                if (!preg_match("/^(25530003)-?([0-9]{7})$/", (int) $el))
                {
                    if((int) $el == 0)
                    {
                        return  response()->json(['message' => 'Empty line or Blank msisdn Found on CSV file !'], 400);
                    }

                    return  response()->json(['message' => 'Incorrect Msisdn Found on CSV file : '. (int) $el], 400);
                }
            }

        }else {
            foreach($array as $el)
            {
                if (!preg_match("/^\+?(255)-?([0-9]{3})-?([0-9]{6})$/", (int) $el))
                {
                    if((int) $el == 0)
                    {
                        return  response()->json(['message' => 'Empty line or Blank msisdn Found on CSV file !'], 400);
                    }

                    return  response()->json(['message' => 'Incorrect Msisdn Found on CSV file : '. (int) $el], 400);
                }
            }

        }





        // if(count($array) > 200)
        // {
        //     return  response()->json(['message' => 'Exceeded maximum 200 Msisdn in CSV file !'], 400);
        // }


        if($request->file('spoc-attachment-file')){
            $SPOCFile = file_get_contents($request->file('spoc-attachment-file'));
            $SPOCFilebase64 = base64_encode($SPOCFile);
        }else{
            $SPOCFilebase64=null;
        }

        if($request->file('TIN-file')) {
            $TINFile = file_get_contents($request->file('TIN-file'));
            $TINFilebase64 = base64_encode($TINFile);
        }else{
            $TINFilebase64=null;
        }

        if($request->file('business-licence-file')) {
            $LicenceFile = file_get_contents($request->file('business-licence-file'));
            $LicenceFilebase64 = base64_encode($LicenceFile);
        }else{
            $LicenceFilebase64=null;
        }

        if($request->file('BRELA-file')) {
            $BRELAFile = file_get_contents($request->file('BRELA-file'));
            $BRELAFilebase64 = base64_encode($BRELAFile);
        }else{
            $BRELAFilebase64=null;
        }

        $body = [
            'CompanyName' => $request->input('business-name'),
            'CompanyEmail' => $request->input('company-email'),
            'Category' => $request->input('registrationCategory'),
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

            'Tin' => $request->input('TIN'),
            'TinDoc' => $TINFilebase64,
            'BusinessLicenseNo' => $request->input('business-licence'),
            'BusinessDoc' => $LicenceFilebase64,
            'SpocPhone' => $SPOC['msisdn'],
            'SpocEmail' => $SPOC['email'],
            'BrelaDoc' => $BRELAFilebase64,

            'VillageID' => $SPOC['village']
        ];

        $url = '/BulkRegistration';

        $data = $this->postRequest($url, $body);

        unset( $body['SIGNATURE']);
        unset( $body['TinDoc']);
        unset( $body['BusinessDoc']);
        unset( $body['BrelaDoc']);
        unset( $body['PHOTO']);
        unset( $body['SpocAttachment']);
        unset( $body['MsisdnList']);

        Log::channel('Bulk-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0 ) {
            $request->session()->forget('NIDAdata');
            $request->session()->forget('spoc');
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 200);
        }elseif($data['ID'] == 1 && $data['Description'] == 'Index was out of range. Must be non-negative and less than the size of the collection'){
            return response()
                ->json([
                    'message' => 'Please check company name. Should contain atleast 2 words e.g ' .$body['CompanyName']. ' LIMITED ' ,
                    'status' => $data['ID']
                ], 400);
        }
        elseif ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        }

        return response()
            ->json([
                'message' => 'Sorry, Something went wrong . Try again !',
            ], 400);
    }

    public function getRegions()
    {
        $url = 'Imsregions';

        return $this->getRequest($url);
    }

    public function getVillage($Id)
    {
        $url = 'GetVillageByWardID/' . $Id;
        $territory = $this->getRequest($url);

        return $territory;
    }
}
