<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\RegistrationRequest;
use Illuminate\Support\Facades\Log;
use Session;
use Route;

class RegistrationController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_REGISTRAL,ROLE_SPECIAL_REGISTRAL,ROLE_MAKER']);
        $this->middleware(['role:ROLE_SPECIAL_REGISTRAL'])->only(['bulkSecondaryRegistration', 'bulkPrimaryRegistration', 'bulkSpocRegistration', 'diplomatCheck', 'diplomatRegisterPrimary', 'diplomatRegisterSecondary']);
    }

    public function checkPrimary(RegistrationRequest $request)
    {
        if ($request->idType == 'P') {
            $idType = 'P';
            $regType = 'VISI';
        } elseif ($request->idType == 'DP') {
            $idType = 'P';
            $regType = 'DIPS';
        } elseif ($request->idType == 'N') {
            $idType = 'N';
            $regType = 'INDI';
        }

        $body = [
            'IDNumber' => $request->idNumber,
            'IDType' => $idType,
            'UserID' => $this->user['UserID'],
            'RegType' => $regType
        ];

        $url = 'QueryMsisdnListPerID';

        $data = $this->postRequest($url, $body);

        Log::channel('Primary-msisdn-first')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['isNinBlaclisted'] !== 0) {
            return response()->json([
                'message' => 'Customer ID is blacklisted with reason : ' .  $data['BlacklistReason'],
                'status' => $data['isNinBlaclisted']
            ], 400);
        } elseif ($data['icapResponse'] == null && $data['isNinBlaclisted'] == 0) {
            if (is_array($data['MsisdnStatusPerID'])) {

                $msisdnArray = [];
                $lastKey = array_key_last($data['MsisdnStatusPerID']);

                foreach ($data['MsisdnStatusPerID'] as $key => $value) {
                    if ($value['TcraStatus'] == 'PRIMARY') {
                        return response()->json([
                            'message' => 'Customer has already set primary number : ' .  $value['Msisdn'],
                            'status' => $value['Msisdn']
                        ], 400);
                    }

                    if ($value['TcraStatus'] == '') {
                        array_push($msisdnArray,  $value['Msisdn']);
                    }

                    if ($lastKey == $key && count($msisdnArray) == 0) {
                        return response()->json([
                            'message' => 'Customer has no additional numbers to set as primary !',
                            'status' => $data['icapResponse']
                        ], 400);
                    }
                }

                $request->session()->put(['previous-route' => Route::current()->getName(), 'msisdnPrimary' => $msisdnArray, 'IDPrimary' => $request->idNumber]);

                return response()->json(null, 200);
            }
        } elseif ($data['icapResponse'] !== null) {
            return response()->json([
                'message' => 'Error occured : ' .  $data['icapResponse'],
                'status' => $data['isNinBlaclisted']
            ], 400);
        } else {
            return response()->json([
                'message' => 'An error has occured !',
                'status' => $data['icapResponse']
            ], 400);
        }
    }

    public function getMsisdnPrimary()
    {
        if (session::has('msisdnPrimary')) {
            return response()->json(session::get('msisdnPrimary'), 200);
        } else {
            return response()->json(null, 400);
        }
    }

    public function setPrimary(RegistrationRequest $request)
    {
        $body = [
            'Msisdn' => $request->msisdnPrimary,
            'IdNumber' =>  $request->session()->get('IDPrimary'),
            'NidaTransctionID' => NULL,
            'UserID' => $this->user['UserID'],
        ];

        $url = 'DefinePrimaryNumber';

        $data = $this->postRequest($url, $body);

        Log::channel('Primary-msisdn-second')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            return response()->json([
                'message' => 'Successfully preset Primary MSISDN !',
                'status' => $data['ID']
            ], 200);
        } elseif ($data['ID'] == 2) {
            return response()->json([
                'message' => 'Something went wrong. Please try again !',
                'status' => $data['ID']
            ], 400);
        } elseif ($data['ID'] == 1) {
            return response()->json([
                'message' => 'Customer has already set primary cell number !',
                'status' => $data['ID']
            ], 400);
        } else {
            return response()->json([
                'message' => 'Sorry, An error has occured !',
                'status' => $data['ID']
            ], 200);
        }
    }

    public function checkSecondary(RegistrationRequest $request)
    {
        if ($request->idType == 'P') {
            $idType = 'P';
            $regType = 'VISI';
        } elseif ($request->idType == 'DP') {
            $idType = 'P';
            $regType = 'DIPS';
        } elseif ($request->idType == 'N') {
            $idType = 'N';
            $regType = 'INDI';
        }

        $body = [
            'IDNumber' => $request->idNumber,
            'IDType' => $idType,
            'UserID' => $this->user['UserID'],
            'RegType' => $regType
        ];

        $url = 'QueryMsisdnListPerID';

        $data = $this->postRequest($url, $body);

        Log::channel('Secondary-msisdn-first')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['isNinBlaclisted'] !== 0) {
            return response()->json([
                'message' => 'Customer ID is blacklisted with reason : ' .  $data['BlacklistReason'],
                'status' => $data['isNinBlaclisted']
            ], 400);
        } elseif ($data['icapResponse'] == null && $data['isNinBlaclisted'] == 0) {
            if (is_array($data['MsisdnStatusPerID']) && count($data['MsisdnStatusPerID']) > 0) {
                $msisdnArray = [];
                $lastKey = array_key_last($data['MsisdnStatusPerID']);

                foreach ($data['MsisdnStatusPerID'] as $key => $value) {

                    if ($value['TcraStatus'] == '') {
                        array_push($msisdnArray,  [$value['Msisdn'], $value['RegistrationType']]);
                    }

                    if ($lastKey == $key && count($msisdnArray) == 0) {
                        return response()->json([
                            'message' => 'Customer has no additional numbers to set as secondary !',
                            'status' => $data['icapResponse']
                        ], 400);
                    }
                }
                $request->session()->put(['previous-route' => Route::current()->getName(), 'msisdnSecondary' => $msisdnArray, 'IDSecondary' => $request->idNumber]);

                return response()->json(null, 200);
            }
        } elseif ($data['icapResponse'] !== null) {
            return response()->json([
                'message' => 'Error occured : ' .  $data['icapResponse'],
                'status' => $data['isNinBlaclisted']
            ], 400);
        } else {
            return response()->json([
                'message' => 'An error has occured !',
                'status' => $data['icapResponse']
            ], 400);
        }
    }

    public function getMsisdnSecondary()
    {
        if (session::has('msisdnSecondary')) {
            return response()->json(session::get('msisdnSecondary'), 200);
        } else {
            return response()->json(null, 400);
        }
    }

    public function setSecondary(RegistrationRequest $request)
    {
        $body = [
            'CustomerMsisdn' => $request->msisdnSecondary[0],
            'CustomerNin' =>  $request->session()->get('IDSecondary'),
            'NidaTransactionID' => NULL,
            'reasonCode' => $request->tcraReason,
            'registrationCategoryCode' => $this->getRegistrationCode($request->msisdnSecondary[1]),
            'UserID' => $this->user['UserID'],
        ];

        $url = 'DefineSecondaryMsisdn';

        $data = $this->postRequest($url, $body);

        Log::channel('Secondary-msisdn-second')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['TcraResponseCode'] == 151) {
            return response()->json([
                'message' => 'Customer NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 152) {

            return response()->json([
                'message' => 'Agent NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 153) {
            return response()->json([
                'message' => 'Customer has reached maximum SIM cards !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 154) {
            return response()->json([
                'message' => 'Customer reason not accepted by TCRA. Please choose another !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 156) {
            return response()->json([
                'message' => 'Duplicate customer msisdn from TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 4) {
            return response()->json([
                'message' => 'You are not Authorised to access this page !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 150) {
            if ($data['IcapResponseCode'] == 0) {
                return response()->json([
                    'message' => 'Successfully set Secondary MSISDN !',
                    'status' => $data['TcraResponseCode']
                ], 200);
            }
        } else {
            return response()->json([
                'message' => 'Sorry, An error has occured !',
                'status' => '999'
            ], 400);
        }
    }

    public function checkMsisdnNIDA(RegistrationRequest $request)
    {
        $body = [
            'CustomerMsisdn' => $request->msisdn,
            'CustomerIDNumber' => $request->NIN,
            'UserID' => $this->user['UserID'],
            'IDType' => 'N',
            'RegType' => 'INDI'
        ];

        $url = 'IDNumberAndMsisdnCheck2';

        $data = $this->postRequest($url, $body);

        Log::channel('New-msisdn-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['MsisdnCountPerNIN'] >= 5) {
            return response()->json(['message' => 'Customer NIN has already registered five(5) or more MSISDN !'], 400);
        } elseif ($data['blacklisted'] !== 0) {
            return response()->json(['message' => 'Customer NIN is blacklisted with reason: ' . $data['BlacklistedReason']], 400);
        } elseif ($data['RegistrationStatus'] === "REGISTERED") {
            return response()->json(['message' => 'Msisdn already registered !'], 400);
        }

        //Customer is Bio-Registered
        elseif ($data['BioregStatus'] === 'Y' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is already Biometrically registered. Thank you!'], 400);
        } //Customer is E-Registered not Bio-Registered
        elseif ($data['BioregStatus'] === 'N' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is already registered, but NOT Bio-registered. Thank you!'], 400);
        } //Customer is New
        elseif (($data['BioregStatus'] === 'N' && $data['RegistrationStatus'] === 'NONE') || ($data['BioregStatus'] === 'Y' && $data['RegistrationStatus'] === 'NONE')) {

            if (is_array($data['MsisdnStatusPerIDNumber'])) {
                foreach ($data['MsisdnStatusPerIDNumber'] as $key => $value) {

                    if ($value['TcraStatus'] == 'PRIMARY') {
                        session::put(['previous-route' => Route::current()->getName(), 'msisdnSecondaryNIDA' => $request->msisdn, 'NINSecondaryNIDA' => $request->NIN]);
                        return response()->json(['status' => 1], 200);
                    }
                }

                session::put(['previous-route' => Route::current()->getName(), 'msisdnPrimaryNIDA' => $request->msisdn, 'NINPrimaryNIDA' => $request->NIN]);
                return response()->json(['status' => 2], 200);
            } elseif ($data['MsisdnStatusPerIDNumber'] == null) {
                session::put(['previous-route' => Route::current()->getName(), 'msisdnPrimaryNIDA' => $request->msisdn, 'NINPrimaryNIDA' => $request->NIN]);
                return response()->json(['status' => 2], 200);
            }
        } elseif ($data['errorMsg'] !== null) {
            return response()->json(['message' => 'An error occured: ' . $data['errorMsg']], 400);
        } else {
            return response()->json(['message' => 'An error occured !', 'status' => $data], 400);
        }
    }

    public function registerPrimaryNIDA(RegistrationRequest $request)
    {
        $deviceDetails = [
            'DeviceIMEI' => null,
            'DeviceModel' => null,
            'DeviceSerialNo' => null,
        ];

        $body = [
            'NIN' => $request->session()->get('NINPrimaryNIDA'),
            'FingerCode' => $request->fingerCode,
            'FingerData' => $request->fingerData,
            'MSISDN' => $request->session()->get('msisdnPrimaryNIDA'),
            'UserID' => $this->user['UserID'],
            'deviceDetails' => $deviceDetails,
            'Platform' => 'web'
        ];

        $url = 'RegisterNewPrimary';

        $data = $this->postRequest($url, $body);

        unset($body['FingerData']);

        Log::channel('Primary-msisdn-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RegStatusCode'] == '0' && $data['NidaErroCode'] == '0') {
            $request->session()->forget('msisdnPrimaryNIDA');
            $request->session()->forget('NINPrimaryNIDA');

            return response()
                ->json([
                    'message' => 'Registration successful !',
                    'status' => null
                ], 200);
        } elseif ($data['NidaErroCode'] == 01) {
            return response()
                ->json([
                    'message' => 'Customer Biometric verification failed',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['NidaErroCode'] == 132) {
            return response()
                ->json([
                    'message' => 'Customer NIN not found',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['NidaErroCode'] == 141) {
            return response()
                ->json([
                    'message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['NidaErroCode'] == 172) {
            return response()
                ->json([
                    'message' => 'Customer has defaced fingers. Thanks !',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['NidaErroCode'] !== 0) {
            return response()
                ->json([
                    'message' => $data['NidaErrorMessage'],
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == 90) {
            return response()
                ->json([
                    'message' => 'Customer Msisdn already exist !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == 91) {
            return response()
                ->json([
                    'message' => 'Please wait for 30 mins before registering again !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == 92) {
            return response()
                ->json([
                    'message' => 'Failed NIDA verification !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == 93) {
            return response()
                ->json([
                    'message' => 'Error : Could not connect to NIDA !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == 94) {
            return response()
                ->json([
                    'message' => 'Error: NIDA Connection Timed out !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == 95) {
            return response()
                ->json([
                    'message' => 'Error: Failed to update iCAP !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == 999) {
            return response()
                ->json([
                    'message' => 'Error : General error !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => 'An error has occured !',
                    'status' => $data['RegStatusCode']
                ], 400);
        }
    }

    public function registerSecondaryNIDA(RegistrationRequest $request)
    {
        $deviceDetails = [
            'DeviceIMEI' => null,
            'DeviceModel' => null,
            'DeviceSerialNo' => null,
        ];

        $body = [
            'NIN' => $request->session()->get('NINSecondaryNIDA'),
            'FingerCode' => $request->fingerCode,
            'FingerData' => $request->fingerData,
            'MSISDN' => $request->session()->get('msisdnSecondaryNIDA'),
            'UserID' => $this->user['UserID'],
            'deviceDetails' => $deviceDetails,
            'Platform' => 'web',
            'reasonCode' => $request->tcraReason
        ];

        $url = 'RegisterNewSecondary';

        $data = $this->postRequest($url, $body);

        unset($body['FingerData']);

        Log::channel('Secondary-msisdn-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RegStatusCode'] == '0' && $data['NidaErroCode'] == '0' && $data['TcraResponseCode'] == '150') {
            $request->session()->forget('msisdnSecondaryNIDA');
            $request->session()->forget('NINSecondaryNIDA');

            return response()
                ->json([
                    'message' => 'Registration successful !',
                    'status' => null
                ], 200);
        } elseif ($data['NidaErroCode'] == '01') {
            return response()
                ->json([
                    'message' => 'Customer Biometric verification failed',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['NidaErroCode'] == '132') {
            return response()
                ->json([
                    'message' => 'Customer NIN not found',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['NidaErroCode'] == '141') {
            return response()
                ->json([
                    'message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['NidaErroCode'] == '172') {
            return response()
                ->json([
                    'message' => 'Customer has defaced fingers. Thanks !',
                    'status' => $data['NidaErroCode']
                ], 400);
        } elseif ($data['TcraResponseCode'] == 151) {
            return response()->json([
                'message' => 'Customer NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 152) {
            return response()->json([
                'message' => 'Agent NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 153) {
            return response()->json([
                'message' => 'Customer has reached maximum SIM cards !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 154) {
            return response()->json([
                'message' => 'Customer reason not accepted by TCRA. Please choose another !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 156) {
            return response()->json([
                'message' => 'Duplicate customer msisdn from TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['RegStatusCode'] == '90') {
            return response()
                ->json([
                    'message' => 'Customer Msisdn already exist !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == '91') {
            return response()
                ->json([
                    'message' => 'Please wait for 30 mins before registering again !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == '92') {
            return response()
                ->json([
                    'message' => 'Failed NIDA verification !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == '93') {
            return response()
                ->json([
                    'message' => 'Error : Could not connect to NIDA !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == '94') {
            return response()
                ->json([
                    'message' => 'Error: NIDA connection timed out !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == '95') {
            return response()
                ->json([
                    'message' => 'Error: Failed to update iCAP !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegStatusCode'] == '999') {
            return response()
                ->json([
                    'message' => 'Error : General error !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => 'An error has occured !',
                    'status' => $data['RegStatusCode']
                ], 400);
        }
    }


    public function checkMsisdnVisitor(RegistrationRequest $request)
    {
        $body = [
            'CustomerIDNumber' => $request->passportNumber,
            'CustomerMsisdn' => $request->msisdn,
            'IDType' => 'P',
            'UserID' => $this->user['UserID'],
            "RegType" => 'VISI'
        ];

        $url = 'IDNumberAndMsisdnCheck';

        $data = $this->postRequest($url, $body);

        // $data = array (
        //     "BlacklistedReason" =>  null,
        //     "blacklisted" =>  0,
        //     "MsisdnCountPerNIN" =>  0,
        //     "BioregStatus" =>  "N",
        //     "RegistrationStatus" =>  "NONE",
        //     "MsisdnStatusPerIDNumber" =>  [
        //         [
        //             "Msisdn" => "255765031302",
        //             "TcraStatus" => "PRIMARY",
        //             "RegistrationType" => "INDI",
        //         ]
        //     ],
        //     "errorMsg" =>  "No MSISDNs found for Party Id FGHF87787 Type - P"
        // );

        Log::channel('New-msisdn-visitor-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['MsisdnCountPerNIN'] >= 5) {
            return response()->json(['message' => 'Customer has already five(5) or more MSISDN registered !'], 400);
        } elseif ($data['blacklisted'] !== 0 || $data['BlacklistedReason'] !== null) {
            return response()->json(['message' => 'Customer NIN is blacklisted with reason: ' . $data['BlacklistedReason']], 400);
        } elseif ($data['RegistrationStatus'] === "REGISTERED") {
            return response()->json(['message' => 'Msisdn already registered !'], 400);
        }

        //Customer is New
        elseif (($data['BioregStatus'] === 'N' && $data['RegistrationStatus'] === 'NONE') || ($data['BioregStatus'] === 'Y' && $data['RegistrationStatus'] === 'NONE')) {

            if (is_array($data['MsisdnStatusPerIDNumber'])) {
                foreach ($data['MsisdnStatusPerIDNumber'] as $key => $value) {

                    if ($value['TcraStatus'] == 'PRIMARY') {
                        Session::put(['previous-route' => Route::current()->getName(), 'passportSecondaryVisitor' => $request->passportNumber, 'msisdnSecondaryVisitor' => $request->msisdn]);
                        return response()->json(['status' => 1], 200);
                    }
                }
                Session::put(['previous-route' => Route::current()->getName(), 'passportPrimaryVisitor' => $request->passportNumber, 'msisdnPrimaryVisitor' => $request->msisdn]);
                return response()->json(['status' => 2], 200);
            } elseif ($data['MsisdnStatusPerIDNumber'] == null) {
                Session::put(['passportPrimaryVisitor' => $request->passportNumber, 'previous-route' => Route::current()->getName(), 'msisdnPrimaryVisitor' => $request->msisdn]);
                return response()->json(['status' => 2], 200);
            }
        } elseif ($data['errorMsg'] !== null) {
            return response()->json(['message' => 'An error occured: ' . $data['errorMsg']], 400);
        } else {
            return response()->json(['message' => 'An error occured !', 'status' => $data], 400);
        }
    }

    public function registerPrimaryVisitor(RegistrationRequest $request)
    {
        if ($request->get('fingerCode') == "L1") {
            $fingerDataL1 = $request->get('fingerData');
        } else {
            $fingerDataL1 = null;
        }

        if ($request->get('fingerCode') == "L2") {
            $fingerDataL2 = $request->get('fingerData');
        } else {
            $fingerDataL2 = null;
        }

        if ($request->get('fingerCode') == "L3") {
            $fingerDataL3 = $request->get('fingerData');
        } else {
            $fingerDataL3 = null;
        }

        if ($request->get('fingerCode') == "L4") {
            $fingerDataL4 = $request->get('fingerData');
        } else {
            $fingerDataL4 = null;
        }

        if ($request->get('fingerCode') == "L5") {
            $fingerDataL5 = $request->get('fingerData');
        } else {
            $fingerDataL5 = null;
        }

        if ($request->get('fingerCode') == "R1") {
            $fingerDataR1 = $request->get('fingerData');
        } else {
            $fingerDataR1 = null;
        }

        if ($request->get('fingerCode') == "R2") {
            $fingerDataR2 = $request->get('fingerData');
        } else {
            $fingerDataR2 = null;
        }

        if ($request->get('fingerCode') == "R3") {
            $fingerDataR3 = $request->get('fingerData');
        } else {
            $fingerDataR3 = null;
        }

        if ($request->get('fingerCode') == "R4") {
            $fingerDataR4 = $request->get('fingerData');
        } else {
            $fingerDataR4 = null;
        }

        if ($request->get('fingerCode') == "R5") {
            $fingerDataR5 = $request->get('fingerData');
        } else {
            $fingerDataR5 = null;
        }

        $fingerArray = array($fingerDataL1, $fingerDataL2, $fingerDataL3, $fingerDataL4, $fingerDataL5, $fingerDataR1, $fingerDataR2, $fingerDataR3, $fingerDataR4, $fingerDataR5);

        //$rightThumb = "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";

        $immigrationReq = [
            'DocumentNo' => $request->session()->get('passportPrimaryVisitor'),
            'IssuingCountry' => trim($request->get('issuingCountry')),
            'RThumb' => $fingerDataR1,
            'RIndex' => $fingerDataR2,
            'RMiddle' => $fingerDataR3,
            'RRing' => $fingerDataR4,
            'RLittle' => $fingerDataR5,
            'LThumb' => $fingerDataL1,
            'LIndex' => $fingerDataL2,
            'LMiddle' => $fingerDataL3,
            'LRing' => $fingerDataL4,
            'LLittle' => $fingerDataL5
        ];

        $body = [
            'immigrationReq' => $immigrationReq,
            'Msisdn' => $request->session()->get('msisdnPrimaryVisitor'),
            'UserID' => $this->user['UserID'],
            'Platform' => 'web',
            'RegType' => 'New'
        ];

        $url = 'VisitorNewPrimary';

        $data = $this->postRequest($url, $body);

        foreach ($immigrationReq as $key => $value) {
            if (in_array($value, $fingerArray) && ($value !== null)) {
                unset($key);
            }
        }

        Log::channel('Primary-msisdn-visitor-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RegistrationStatusCode'] == 0 && $data['VerificationStatusCode'] == 0) {
            $request->session()->forget('msisdnPrimaryVisitor');
            $request->session()->forget('passportPrimaryVisitor');

            return response()
                ->json([
                    'message' => 'Registration successful !',
                    'status' => null
                ], 200);
        } elseif ($data['VerificationStatusCode'] !== 0) {
            return response()->json(['message' => 'Customer Biometric Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['RegistrationStatusCode'] == '90') {
            return response()
                ->json([
                    'message' => 'Customer Msisdn already exist !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 91) {
            return response()
                ->json([
                    'message' => 'Please wait for 30 mins before registering again !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 92) {
            return response()
                ->json([
                    'message' => 'Failed NIDA verification !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 93) {
            return response()
                ->json([
                    'message' => 'Error : Could not connect to NIDA !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 94) {
            return response()
                ->json([
                    'message' => 'Error: Immigration Connection Timed out !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 95) {
            return response()
                ->json([
                    'message' => 'Error: Failed to update iCAP !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 999) {
            return response()
                ->json([
                    'message' => 'Error : General error !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 80) {
            return response()
                ->json([
                    'message' => 'Error : Minor not allowed for this registration !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => 'An error has occured !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        }
    }

    public function registerSecondaryVisitor(RegistrationRequest $request)
    {
        if ($request->get('fingerCode') == "L1") {
            $fingerDataL1 = $request->get('fingerData');
        } else {
            $fingerDataL1 = null;
        }

        if ($request->get('fingerCode') == "L2") {
            $fingerDataL2 = $request->get('fingerData');
        } else {
            $fingerDataL2 = null;
        }

        if ($request->get('fingerCode') == "L3") {
            $fingerDataL3 = $request->get('fingerData');
        } else {
            $fingerDataL3 = null;
        }

        if ($request->get('fingerCode') == "L4") {
            $fingerDataL4 = $request->get('fingerData');
        } else {
            $fingerDataL4 = null;
        }

        if ($request->get('fingerCode') == "L5") {
            $fingerDataL5 = $request->get('fingerData');
        } else {
            $fingerDataL5 = null;
        }

        if ($request->get('fingerCode') == "R1") {
            $fingerDataR1 = $request->get('fingerData');
        } else {
            $fingerDataR1 = null;
        }

        if ($request->get('fingerCode') == "R2") {
            $fingerDataR2 = $request->get('fingerData');
        } else {
            $fingerDataR2 = null;
        }

        if ($request->get('fingerCode') == "R3") {
            $fingerDataR3 = $request->get('fingerData');
        } else {
            $fingerDataR3 = null;
        }

        if ($request->get('fingerCode') == "R4") {
            $fingerDataR4 = $request->get('fingerData');
        } else {
            $fingerDataR4 = null;
        }

        if ($request->get('fingerCode') == "R5") {
            $fingerDataR5 = $request->get('fingerData');
        } else {
            $fingerDataR5 = null;
        }

        $fingerArray = array($fingerDataL1, $fingerDataL2, $fingerDataL3, $fingerDataL4, $fingerDataL5, $fingerDataR1, $fingerDataR2, $fingerDataR3, $fingerDataR4, $fingerDataR5);

        //$rightThumb = "/6D/qAB5TklTVF9DT00gOQpQSVhfV0lEVEggMzEyClBJWF9IRUlHSFQgNDczClBJWF9ERVBUSCA4ClBQSSAtMQpMT1NTWSAxCkNPTE9SU1BBQ0UgR1JBWQpDT01QUkVTU0lPTiBXU1EKV1NRX0JJVFJBVEUgMC43NTAwMDD/pAA6CQcACTLTJjwACuDzGoQBCkHv8bwBC44nZT8AC+F5pN0ACS7/VdMBCvkz0bYBC/KHHzcACiZ32gz/pQGFAgAsA5lyA7giA5lyA7giA5lyA7giA5lyA7giA7NDA9cdA6uHA83VA6b8A8hiA6/aA9MGA6ncA8vVA6OsA8RoA6eEA8kEA60CA8+cA6AXA8AcA58tA78DA6CAA8CaA6dhA8jbA7DaA9Q5A6sEA804A7GcA9UhA6+rA9LNA8DdA+dvA7f4A9zEA8MpA+oxA73XA+PPA9O/A/4YA8YxA+3UA9bqAhnKA8FjA+gRA8pOA/LDA70AA+LNA8azA+5xA8idA/C8A9dLAhnWA8kNA/FDA93MAhqeA6+cA9K7A7VtA9m2A8yTA/V9A8L5A+n4A7t5A+D4A8AoA+aXA8w0A/ULA8rEA/NSA8q4A/NDA8TpA+xLA+AmAhrmA9dTAhnXA9NoA/2wA8yqA/WZA+aFAhuqA913AhqTA+mzAhwLA7r5A+BeAht5AiD4A8hYA/BqAh06AiMTA8UWA+yAA86nA/f8Ah/YAiY3AiIMAijcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/6IAEQD/AdkBOAJW+wRD9AAAAP+mAE0AAAEDAwEDBgkJAwsCBwAAALUBsrOxtrcCA7C4BAWur7m6BgcICQoLrbvCDA0PqausvL3DDhCqERKkpaanqL7AwcQTvxwdHiCio8f/owADAP1+vj4+Pj/f/P1+v1+vj4/1wu3+/j9fr4/PZTi/9/r4/wBLE+r7fH6J7dPtvR8fn+v2+31+vTd/8P6/0/t9f7ffdf8AOPr/AE/j6/fr0f8AzPv7dPv7dOr/AF7+3Xp1Xt1n6/z7detb9en2+Pjt9um/X6/1/v8AHx/v810/x/8AP/v9Pj4+P9/mf4/t/f8Ar+v1+vj4/H26ff7835SPmQRCKKFo6cK4m7L7KrE7jV9bJw6FfV1exL63Hb0ENTV0o9EtNXut1Ny9SOQDkOCvkNDnhL5mieEjDYYK0aile2aKj3L7dxOhY8N52Uw1WxY7s1W6drE0c7w2YKmcpSb68h5uznx/+918cjfxEFciQFUUdp6DTzKjUChDvMMXaNQU70UFppuGGrXVSaCamhWopJvHwTY3dkOR1yTx7TPWfztT9jlPoQsnmyWppw8S3UI/oSZdQDlHJqOAKHObXBWTmLFBB1gN8iTnkIpZt0UenUauycoI1IEi3ciKVUEJAtSbPeYVJYs8Sb1mROSRObbwJCKSIEaeoA6qQRDTZqlEASKac1JNnJfOBDaMI4psCd7oaFeZOQ4XHdxd1PC7hahK6geIhTaRTxLTTciw8YskaHLPMWCifyoVxEfoaNieufyIJk+kAh5goSbHmIWLeEuectCBEZ4ERGruKHjFkC7inlNXLLJepzlZJIXEAperuBEcd/fv3VSbGaiMTKfSgvlYQCcQgGxK7fm4s1ZDU07JETTu3jmbVAJiktTGjVVupRtCC3HsVHyEWmi9Wpoe0mrlbTfKhRBTVj5TGIuXykvkTjTCyTOMuc32oUHM9/wunXnMWPdu+MPvv18ZxqOKMzPO7XSCDO/pCT261VV6x9/r033nt6DPw/b7fdT1kfbv+D5OH771wp84Zb3vzIR6lk8YpifTsCl+EVqIlScXOZtERqTmBECxREznTizEKmmPR2nIlgLC9ccWmam0DO2hcdf40YpGCxTrXZ9aI97V4GafBrdzRJtxqs3Lltdh4dbNmcRAX1XZvJrdG6I0MtZOWXFawVpnPvfbth2NEaOQsxXjkQrCaJ2d3UVyASbF2oIUq34nDUklyEzPCAVzinhNUUuLFXkIijFJfiakWXV2ejsxZJv6ZtS7cV83Ff8A6BH0esU+QSNQ8yatW0TxNrRqLPK9rV1ETmxGoxW7OcU1Q1aHNhG00WnM5ONxDyU8GjVyEJqyaOTijCwTQgU4pd7k1bRsIl8L7VdqZQKG3UWU1c0RzYyGo07NjRQgkESW0TRNS9SXvfOQUiOQKKbCagLGCiNFlsbiKy2zaQWSETskfKC4hNqzW/hOFZRWJnjFvcsQgniQU0+ETzuVarLuvTfcjUq/mMufKf8AXH85JL+hiI/U0GoX5SkY3eXGeIUM3LV4HmSXNn4xMkGKkR3sQFY1Oi4UlbORuanRuNObRbvQrzUIXqcGFp3iiJygqBSUOKwzNOXX3hbUgpFNZmd3xx2WMd+P4ipO+Ap0rmzoJRUy4Nw2vGSMsRcgXtFBCiuLJ48SgvdMDGs2jlIGrVKr4fOnYLAsb468oI69mt6KmSvB37KJqd3CvGLFU6/je8vt4k1dYQZv5lCiHZPRlNqCPU07ofrP5WgPkS0yP1FuBTh4kiqalyT0mpep4ng1Mvwc1LBE1nKFzUFKyPDV9kSCmcJ6m0y6RexHSxqT33Gi89ui9+L406/z06uKiK+2ZhrfVG7ri2p2vgUUedRSyFYr2fadc7Qit3qG3bednWpoTNsm7qPeG+pc0Z7U0wihJNjib4SCaiYjaeLanhCMWRCupbNi4pBW0OOcjTVy2hzK8KqRHaPvOJ4ic4loUPOZYhYHpujo7hX7VWp84Pc+T/nLP3yzPnIK1cY/OvApnnIm8CB5mhU2zfxlNRNqHKbUzVlljmKcuLV1KFGrxTle/FDFLgIWasrIAjT2kU4aMqIuxq3ubf5++DdqlFdJ5rtDPcVodCmnt369U86F8SFtzT6IBGKaARoRhFI1HJfPdBI3Scq1ONSRNNTKBqWc8RCTtWoq5XgixRSV5AiKS8imOc3oulWrhu/COax0omTza6jYon8h8VWn6SIdhXqcIbpdH+xvc+Us/c1H9CS1IehFbTUPTeQVW9PyLUU1FEeEKaljJrJy3C7vUgiWbScOusHwoGpsx8bqhsmjkSTfjFW6LJGcmLjpkQJuR7OCq5dyxSE0ydqclXvafCq9S1dgrYNWicg1ORMpXvoBS1QKu7V73qaBQU0WKPaZAUNbyUs42JJvZAuaN3sdPeriw09++djk69+vEcdL/u3/AB9+R1O6a6L3/D9vtucyqJ278P8Aj6/de/48jtx9emfj3/7/ANe/fxCuvH5vr9v4/j/Ht6Q9pQu7+/q/9C7Xv37+tldKih6OX+0pe+OesmYvbe89DE/vfB1fk6sXcrXfPCBHT6NSqnJkU1fY3lqbWaEG/tMqVsWnbirv2VPDYvu5aj36Li2XqIXQRatS3BTcpx8Rv88b+1VNXac3nfBe3Tfp13RAoKrrlPut00JkQt843zOvfN9BIbVvOznvvsGWXnHGLHlK9Uu3fjOFu1B6mru7qzcRoqTbr26F9cg9HCNuKuLtybcnImA7WDGg2lxVgCtWpOUQJk0S/RptAj0mcKyQu/MFUL+YLraA9Gpmzv1s/cLf0GWp8yANWp55IuLL2njI4iyEl+Ev7dd83QCjnOsvdcLOzoLZyiv3FbEQRyDH9vse3vITgc0JmZv76impL0TJrPeuL1NBsRB1/gMrQ5e0uGYVS3kmjQNDxb5LRtNSpd2qtS2iptVCiMmt8YI2qJ3c1U3rvfttNoORZx+f84uHotQYzr3X8H4qe/IxXM69+/8AlV2/HX68reLvdb/bfhze+3PLJ/j2nfjrDHXIWV1XZvrVLEeN+/b2X5+PfgdeU6Zxb/j2m/sjxCfdX8djOyPQ/K3Ont/frnoR/isvv349bT6QGejh9IpJ8pfaq0HoOu3bI68oPtXXN3wWcyFTvuuy677vnUarOH039l37Gw+HB9rz85XsG3HFkR79+vWd+Caieb50m67ZfunNF1u23vurlKbd7LLTydakUOVrcdcfZjkgpLE6xHZF7rL1Y1VzLcaJvNXd2mPo121A1v7byI4yVWUrrVizUitStM2alQ750uaCa44R3pDvJUEbULrw9y2t+/Rvlb7dONzWXC72JlcSNQhE+RJIZB2CvwJCCm5MnkXwpuR+ZOK1IazzMUvVS/S3bzeXPSKZoh/5Zf7SK1J6gOmrPOtSBcrynIpuXmeJkiMudZ4O00OUwDazUpFrgBvfULVMcL46127UpvftxaiydVxcwT4pdsTb4W64sFOJSzQr44qXeIidmhRVG6EbPNPRLQpsRo3FW82utViGLeKERtCxOccRhCcu18cXwqOcRteVLiJqahoHOZArRsMcyIkitzmaFRFFB8oJ1EWgjPK65xPyjuGqxX6XGnak39RWnU+Qi7uvlP5hD98lqesQ1b+cvYfzehQhcni0Ed7Gp43CG1iu3tGoXL09R29TZ1qLe5p3m3QkkRITUuKdn363Vq4nYKag1kNYR2alaYiik8Q7Uk2jiIJ4TabSNZvSiM0ByapTTkiuWnsXL1U1NjnLVqcRNqaJoNCE5ascRyFEXcuYDOvKRRWXbYzL5Ry5kl3N6h4EQ7VotSX4kgy+tyXPJmrtQlnpShcmr9YtyhM9Xp3EH/iO/oCn7EjQKeUmpNqDxm2KjqnPITmcGd9Pm1BQTYXNgcTkO2RZZOVDFvv169s6N3opcTVIN9zhNXClJcIe7UzUWSnwIudYE00yEku5ayTk9RDW/BCw0KyCbLRqTRRFasy9BOTLUt7qQPDE98t3kx6NEaYCIAhGpohq2XayG0UQt0F3tNhppgGgk5EmEkTFSnhlFq2KMvwLUyPERHlLTUE4eZg5At+k2xS/pgn/AO4j9g1R8xGrv5Cigop5zRKuCs8yIGS2TwIoQRcEE2k2CK6x7PauGK53tq4hvbpZcHtBQcRuS3iJRNS+RY91I4INOaxWaZCtsEajRJJEbheptg0GBLaHJsIeKhDtok5yXUERFq5tZHkFJGho05e5E9gU1OYM0GpqXyuaigr1B+NqrkGpC+nhLp2MicDwDtWrvUDzt2chT0IERcs9BBvc4PkXEAb+r1DQf/+mAIIBAAIBAQQEBwUIExYRBg8AALO1AQIDBLK2BQYHCAkKCwwNsbcODxARaRITFBUWHh+wFxgZGhscHSAhIiMkJSgpKzdquCYqLC0uLzAxMjM0OTpAQkRGSUtPr7knNTg7PT4/QUNFR0hKTU5QUjZUVlhgrjxMUVNVV1lcXV5fYq26u/+jAAMB9gd7CnwMxeWYmM1jq7gRydoI7rEsLjiNiGN85MuIn8yOjBhjGPbMQ2c27ZoMVi5ky4xMGLpdmYKhEogRMDiHtJi2KMZz/wDnb29sTqODF2dv/wCmczMwUsax2yBBrq4rDWYMZ16pROsaxnEHOJ1nVziFs56zM7YymYZmc0JCzWYnVLLMTBjD1c9h/lfKMwV/37dRmLue0Kwfzc5OxqM7GO0w+0mNyfdkzmD92Nis02V4rnHXL2ccSYwLWO4z8i+JHHQsw9BsDiFZOTfMxRowjEsZ1KbMc0XKAglEWylkVOxoYY4jWaWxkxWZjI6mBmIUQIOvXqwygO+MgMwQhd65IEKzC72CxWAJhjQZrFNiwzIBBgrjNlIURKMXM5QspmGuGZcZGZxrm6quSdtnDCgcmxRFxkeBSQwHQjjMfBj3H0Pcws8gstHEhbBTwdRp1WhGAG7H2zEMLMjcCzilyRtkIEWJhrrSILBmQypXYQyTOVTDM12F69hFXNBH2pMoNIOIVljTFykwhpgWnOHEDFPZXDcxAMXSMXOGjUjlJie3+f3AYKwRy5IkKdlmFzlGdtXGAmYMyx1H+cSv5UYNiY7TJjGMYjuZO2MszP5Z2bde0COM8XrHHZZ7eOJ2C/t5qZx4p7CJ4tDzaLO7RGEU3YxzZNW656Gi0jZohM4wu5CxCmBRTWCgmM2JmFFI3IZgQ55EYUNhhQNJ1YUQuMVojS0MI4rDMRhd6kWnENWYVIkaIXzDMIMHJZxhwsYlYNBmGy4wQvmZ6i57QxDOhkrOKcZ3YVjtMQ4lfcwp4McscZccVI0Z5F2Pcr8j5w5kYw4tBSvQsw3bBlSOjsLRolNMxMrdMwLsYYthpikYuqYjM4xGs2MpozGzGGO1CkcYoa64o2bPb7mmZy0tsFnQxGMY5UxY3cwJjHtjRAomc5zGCXNSsAhjGiFIQojcxYI1lAuwG2J2fuybF2M9p14p1w4xM7rOsaMPJtnoOYxXoq/Yed8H3nkR86xjDY1aGJZY3dHRTVjCHFNXUDUmXQs6FNi5TTCy6LizorcyNzBQaCWEEN3Q4GjTnRyQs3KV5MWhpodU4u7RRQcmhCsm5GnwNzuKT5j5XOXo2YdykOBdseCu7otnmrCGyjdpi0uNGLGmmFMCNAXAomOqswWHK5KKFSjHaMxRQRuYoZiOGZNUFCxG5CiJYjo0NJZutmxBzrhNHKGi2aWAdTdLlBqOYXIuOC5oOps0TFHfg0OKIJHjiYGxzLmOgB8gng3PW2IdxqJzdBN2zc4FENQ0NAo5kSFiN2BYeJCJoLZouYgQuNiA06MLsGNFK002KLDTsxYljYUdGjVYJRCJqQhZhyLEaaE5N0ju2brwWmg9BDmQhMZ4lj0lHcw73zEe8ohyIRudA7luQR4Fmml2CMEyFDcjELhGwDAomEIN3qUwjQXc0kwYuwt1axiNZJ2CNjNmnBjfGImL4pjYwTJGlhG71TsgBwMsMgpE1JlcaK5jZWsMRmSYN2MWODfNusUgL/LRwtmFEzwJkmEB3RsGXJwEpjnmwjRl5FJA7iZafgKHzHe4jHg0Rpo2dSBHmcmiEKaWwQSJoXYUU5mIlx2I02yLrgTRw4jZzEdARsNmzRmMZml4sbFMKylgAvi4QvhjZ3YWI3KYhQ4s2bpcI6rExkZgdHVJmnV0M0JupCDEdy4Q5hRMR4hmEOjYieth4Myw6ER6DC6PAw4UReLgIVlTUKGCblYQaZmlt1YlskMRjbrOoQIWDOKOvXsijBiQo7PUI2zApoCsjbECDWGxSDQpfMWZMmIa4aKxRlhWLYcIYzZUhQ5WIEQWNnqxhmMw1i45g3xkYl3HYY4LNGrHBHrmO4EHriiZzxXOAmJjPBxMN3ktJZ4uHBFnbk0uTt16E7NP5F8zDPBuXzuWLHRgiwOZRkLlii2cmGxYzFsRKQhGmjtuwhWSF2dYkYmHYUWEd2EWKCBGysMwgl2KURpGJoxgkIYiUwxisEbjq8B1I6AxNikcRB2Ky4pImgxhmHJpKGDzIzHTFsZxHnhR6YuDyaflI+DS9x4ivI3TYxZWy6sb55INArG+FKC7iN0s02XQmYRsA2S7Cy65hSmjnUYYaYkbMUusIaDTdxq2cAMLlMBJnA0RblOcsIw2KNGguRi0uAjfLsEy8CgMwjuxmWPZN2OVsZ5q0cyxR0Vj8p/u+BCnvfQwNXVos6JGEKLmjGFNPAg3XiTKtFO7WZmiDC5HZ1aII3Rs8Fbu7Esx4COzY0ChjZ5o03dR5PJ2OJRZhyYWYHNhAhyPUfoKY9wQjwaafBrFO7cpzsc3dsQ5kYIQLpchCAtizZit3LiyjYNM5jC42bMIsGI8DGTGMBHTFAuYuZiF2wEGnRwEYBTqNgoIrYuQiQc82BAjdVmA1LqUwjGLshGycWmwcm7GHFoj3PoX7DxPQR8CEYx2fS3ObwIPR1bMY3KIxsoUiQsWGJq8UhGmxsQLtzRBd2miPJLjYLMN2inZ1IQjoU7o7OrwYbG5ZebCMxxWykd2zcOYlmjit2jwaO48Hzo+L4FhU4KLjMcQ37fzzEKxwMbFOpn2ntTK47G65z7fuEmGGmc9e3/6s7EY6BO2P5TMYzOjAJjtkmUIWCZfa9v5JBKLZzM4eqfdM3xZEyL1rCBcc5XNGJiixiZmaxcDVFI1g9vtQsiQhXZn/fqdbjG4HY6/d91wgT2vZ9vYeuLDMQ+4ZmYmU0WdjqZ067Gce0MC9jtuTEe0x19pOu+fuJ1w9ovAr+fbsqZxxT+WHGZ15Ht7Ffyp5JWMEOJHxwHcBHv7ZYLuD1ymchsYmcYy9nBupnqTqQLrgmMnWJhhdFcnX24zjBoQJl+5mMw1WY7NCQKUZ7ZnrmETX24xlye2ZCFkaHDjAY2wQcdnDQWIxsMBzplReuMGYOmDFBHUowwxYgkyVntThZhOGWPVYQz263OrMI5MxNQowMAz1N37gp7U7E64jMcwiBbHHGHKdAQZ1OavVHuXHR8SAnzZoDkLCiJxIRgcWN2iOjF7YuWW4C8MaDlzhaE3BhQQp1QmcOhoMSEYvcsaImoWdXVTD3sYQpoQthbKQKMXYWbZZh1clCVjc0YsxM1jQzfHXGVDVEJ2c4LO3UYzqD2c8Mh2jnNO5Ez7fbPbj29eLHKhnPEIM7dyWxRxI+DnB3lniNlgcWEBcuq6CkxqTMIUEy6LEzHLSXT/ALgObEWxGdYrc0IRyTEYTBoB1jG+CzZSJgI7hQ07KwzEib4WiNYaaFIwYCRLYisdCGhMUOjctmwhFLMxBphWCFhYARVp2YOjwI2EE4OFjTwQcjA59XPeRguO9T2YTwY4fF7iZSnYuW68Mxpj1KbvaExFmcTGW3txFmWOI5zfHaEJgmWFzD2Y5hMzrmZpK/lZMZhCiAvaI2SFnBCmyzFyi+FCFCTtgQh9yQYsbFCXLGJkGFOKLEMTJnizDS6OjYmSzGOhHQbliMIscIQ2QrEYu+QiRhngxhMK8EjZJnjiOITHPEYzPfiLzHwcdseYjHoEBOKFFjioNY5NJEmetOjMU0QpNHZmZlC38jQiUDd9szZg056tPWJimNOXcxAcLhi0AmcNMABtkEocJS2aWyWaLBMJFWgd1KIQGFAYrqUO4gLMRykxHRpawnYhcAzMMQCGjYbZhisaJMJZmcnEgsYueCjBxRxcKKTHjnq8mnNHbuX+lx0UnV5qWy+Icgoy2S7mwpiDrgjRMsFSsAEKwKG5TGDRTCmgi4jGDQ7gaKRSywuwjq7EdQDUi01lWjkWdVsmjC7MZhAFNWNy5DRdEodWmxGw6iRiQXlh0HdpLDjiQbLxKzBhyaIvMfEcd5kXq9BrKJzBM1k4F8Wy7DpiNOpZsR3ykCiF2wWaXDStmJksNkuQnVixwsY000A4yBRTmzAjRDQLJo0tLEYlJBbMdRINYoY2KS7cwrCEaI6GLpY2IwaLuE0O1EysTdstLFM7FFhGHE1c8luI8mJZ5BY8y2OT4noDuG5DpnQ5GKaOnZY0065HFNmPA9uAI6N04DDQtgV0LhMzqRIRhdFI2FoLOmGz3NBA2IQbhHZrLCL3JGGGmxMJMlGAjdu0Qb9bOEb9YtHW5ERaxE2CKXykNnDGCoPDsTrM9szLusXGc5zM8mdRxDPNCYTvTNPsfB7gLDxBRaODWRCLuZcELmhM00DHVc4nb7iDFXXBntQQpsxCES62AxAGFjRLDQ7tiiFlpcwigsxosabJBhTTMxjWDjmMSGzoWSIWWYFaxHKaExMo2UsoYw2xmIbYCGWJ22bZxGnimYTEM7lyDiPEyaPEFzWHkP0B4PqeiU9+DU5ZpsUcCBoR4J6Vs7ERKdjYWjmWx6XEKe9s+BA725qQpKCk4NMUp5tzHIi6Opc0cbot0TcgIGIJzVoxuwYFLjrxShs+Cx5ENHuY/G/OvewHmxGPMaAoN1ojTDUCz3ZmSHFuQjDYswp5MLu7oose5QsbLo8TQKDZ2IbF2LDVWwzC9C5lDcjBbty7ZjzYRMZ6NFHFojRxLFEeRoc3FmP4mjvRhDkMIcyEcc2MOghZjwNCZst3cjtiZtmKlGhGOTUsaqhdjQlmMeLYs7LZRucGNDY2UIFMNRQ1NUiNmzdYK3DVhFIxo1QjdSm4wjAEUuWWFjgxiFFOyRognNBaOi2OKaY/KkTwHLiJuBFEXiFZ65eJYYvaLHQpvj7jO+NMkyQBsm7pmylKwgQmdBizCxpsWGMzmMYcMWYU3NQs06IQacVg1QjGLRG7dVKeDm7RcdHKWYNm4NygKdSmEITDqF80qJuDM00cGBRTycR1OitJyI2I94wf8DxGnop0aMPMvnzAxsaEdGJ3nEKKY97q+o3Ix3ImrydGPJ1ehRDVLljix0WPFKea7LwKTR2dGHEpsw6FnwCjkMY+g/QnmCHJSEI8gTzF0i6lik0LhZhGizcRjoQhcmdGnZhCIsY07Fyh1bkG5RzLOrcjGFOgNNiJB6PNNChYWdSFJRo6sTvY2OTZjTzTxfMQ1XiNnvbkx4MYeDT9oCyFz/F4H7yzD+0aTQuf4v7Td/cbJ+suO43bH7V4H5S5cscW5+Zs2WxZP7TkcH6lOZ6X8J0dDgU/Q8S5xdD7Gksd5sx9h4HNsMbnzPM4txp0LvzJY7iELLu2X9ZRY1PxuzHcsRp+U4N2EOTGKWPjffLDYQjs/Cx0TktO7TCku/0tFHmfkbkfQ0cCP33RI8mwj95uRhZOBcu3I6PpNziQoLnJ1Win3x5Fjc3LMKKdT0sKIruN3Q5vrHZ5ng6GqU+ljd5MeZDzmz3mrCPQ8DV1fFbsae4ps3ORC7R4NMbDoOpwdHVNW7R4JDobkS4dBhwHo6HEsXPQhTS2IxeZCIUw+ops3eKQiGhDYjdpoo90eSUupYgmhuR0btn3yxFu2GxdunEjq2dTubNiMIxbsKYbtmGxR8RsJGzu8XV6D3HIdyO5c0abPvDTY3dhofSNyxRyN2FHiaJyNyx7zYg2xRo2abvMsWOQ03XkkLPQuUR3PEsR4pTzfWc2iji6DobO7sanc0WeRswLFmzZ+MosnoUucBPM+66GjAdRs6Jq0++2OhGzzPwG5Z9JdhwaO52YlGzyKNHQo944HeujDi8GjxLPc00XYUw8X4W5TRCkeiXBsbPqea0xhB2ebo2LpxKSHcU00NzomgedopjRcpjyNmz6E4mrTZ0TQuWe9987mIatj85FIx7i5sXaDi97chzHc5PzFnRsth6FnQhG5HQ9Bq2TV0HgWfneJs+pNWhNDvbO7YeZstz6As6NNPc958A+Y4PmOJ52i5oXYcSxTc/E/Adwni7PqNWk4j77saHe8zV91uDocGmHe8Wi5zeAl2z4C+B6W5ddk0NH0HsXoQsQiU0nRsfOnR2eJzPvGzGHnI0veWGOrHmbHIpdmPqRODo8GOhCPxnnNyMLNO7Gs+47nB4L3kYQgR9JToRofOQsanzkfB0YMIcnU+EsxooLve3Bui/O03eZGEIxdD1j525oRH8DxEj7hGij6E2blyCNk1H8BoWdmnufqaCPoKbp7CFngULuBFH+p/caJTo0PF+Yud5DYobNCn1sH95TS8G7zKf+TDVNA/GNMYe6x+ppu839LcdXmWNH9ZzPxnoKND8hH0JGn+xopNGn8pqlh3f2Oj+5/wC3/6MAAwH7QFjP4lj/AEbvlHtziftNzyhjg3Lv+J+t+FfrdCx/5Ef3tH/BwfJ+ORd/eR7iz9R6n+l7zmx/vNjonzvmCls0fSUHMbvFsbP4Uuan4Q0aA3OhY4Pre54lj9L6Sld24feYug/6HALBd4nrCEeJobhq+sj4FHEuUU08HzGgeBye4/oLOhobG7qlHqbnqLrZaaHiw7yylzZXV0bOhCzzXo2brqcy5YuaLT6Vo9xjCFGqx6HuEaObBsFy5ofE3bHxNjkXPYPrXvPBfEu2PfNnuXRhqKU7kPeOZRdjd0aCnuX5WzyWls6GgxsFEbEfcdWzwPUQKWL6Gm5qFHwELNnkeosaFw0DQouWdQ9LT7pu6lznnZ2zwadSzYu2dDzO5oU0cQjTTD1OhDuDZy7mzDiGo8TzrSuwrRyeb4ru6LusNApjHm8nQ8TYI5cFsQs6LyW58BfGq6EKIGhyWFyl2eD5jm06LTZ5nRdyloI6EO44FngeZhHKxYu5zUNyHE8WLoXVXduu69FpeRqasbt2LRdjY0eL4B4MIRbmjwLOrDzmxZadHi7tnU9QPnYsaLuwGx7hMGKeBRoUvi6uhdp4BGzsQ5PJgWYcz3ngNzc1F6PndcR8QNnR7U0fG6IUWWixu+J6cWaKDk2btnddHuPS2ejfFyiDcj8S8G4Qou0PuGrDvabrCxo9zqcmNzvCnR1Lmzs2LtL6SimwWVhxdzmvR4mpd8zF1ZmHcHguovF6NNLqewDivwh0I/CujRxWkO5j635zkpc5my83uSl1Y3FfMU8T0rtljqbvQ1XkLcjyNyyw0I+dge+w1aY0e+GgBq+gKXzPnNl5HJ5FESzT6Xge/luQh+BYeLZe5fO6j5iMDvKYtn0nECNNijvKNGg9BRoL6C62xTD7wNA7gEWF16C0w+hYhQ+YIwV9i7Pe0JGAKfWvAosaHQpg/Qw99SBMxi/A2fMWLqfqafeaaPnwR7ii4MY0lz4WHi2IBoC8j6ljD3Wj6z1EykVsw+I8xHueR9JR8j+ohoRsH4TXBscy7+B/4bF2FFkbP42zGxYjHoWz/esPsLHoaIvk9vg0DClP1KF3979oK+n2gb4f7v2gPifaAxR9oG3HlzvnP4H/AET/AFP4n+Z+E+R/ef7nlenlcPlEH7Hyyj7QNQPLLPK+PtAWF8uR2fLCPLAPtAgp/ifaCux/7H2gMk/mNGnvP4v6n/U73yjzyrl8tU2X9598+g0fjPJmf8HY90Ppeb/k/I/1ujs7n0vyPxHE+B99/wCZ+44vnfE/EHoXR+Rp8Szq9z8LY/ofA8x+Iu+h0YH1liPiUecPYbHN2LHusbv/AKHyP5D5X3S7RDZ9w+w+R+Z72HFhTseg/MWX874tw++6tPR944Gp6jveh6X9R99/sdH6S53PrfU6r5j8xxeD6Hivqf8AseAR4Pk6tPA+++p/Qed3fWfkfiYfnPsNTuP7x/Y7PB/qeB6Dg/S7v9zxPB/Av3ijkeg5lj438DzPhPJudDylHyeX9rqeo9B6nufjNHyZXQs/rI/WaHe2OJq/ufMf5HunE8DzHA9wo5n/ALuh/a3fcD6WmP8A1bH9p8Af3i8H9B+1+k9j+E+x/wDtf2Gr5RJc/awsftfhfrP4HAo9R5QZ5Mr/AGv+rZ/8T7RGHPtCUI+0LNX/AKP73/Mf2nlUn6jgXLnB/KXHd7n8zo0WfKLY6NH9jTZ0fE+t0dhuR8x94s2NmzqXf6sRp0T9DYs7HgWfreC7hwKfvFl4sfQ0WPhNygsXd3Yp+loIeLS2OJ7HuWxzOh8BxY6PQuaPyF3dg8XUs8D4TZp2OBsbh8hdi0BoaDc4Fj6jd3Rsu563itiA836xo7n+oopOBZ4G5qWPdLMLhRAKdCHmPnPSF2zyLHulGjQED335S7TsUnuLc+Eo2Iw3LFHN9ZYs8wdyHF/Gx4FMLnqPWRiEX5Wx7r3lNP3zd5HuvcfGU7ni/nODsaPA+Vs3aLkbkdji/fe92Pwll0KQ1Lu5sfO2Y6GxwKPW0WeAxs7HoPQaGp52xds3aNjwPlbEbne/W0WIWdWz9J3ELhqd7H4DuNGO4H5jve4+tYHB1eI/1mzq3PkeBo96aJCz7x6SHB5G58TzfiNC79Tq8jQ+A7izqHR5HqLFiMN3U9B7Dudws3Oj8R3PnKI6HEjZ+N8zTswh8B3vgaOr+M+Eoh77C5yNT0HrfiLtNyEAgHxHFscC7T6X5nxbq082jznR1bj6X53V0fQ6DwO57hu6hxaDk+47nE4ljkw+p99aeR6Q5OoWbsWEKdEPwjYNWzs9H3x8WHBuOjofW+LZsR9hweZ4ujTchR6CD7j4LY9j7GxGng+s5nReDoUvicHY98styz8LsUR8Td4PoDRhHds3bvie+cEux0N3dsXX2Gzq9ALtz6AIeBC5Dzn0HM5uhGmg+E3HmU0WItGj9gH6XU8DYhCwx+NsHoLlFg1fY8VsbP6X0MGw6l31tY70YXCwXCH5XQ94+g2eLGGqWZn9Dcs00xpixhH627H4H77HVY7Fx1frKbFKuoEKWJ+Q4Lc/rabN3Qu3PysKKC5E0XYV/A8iPAdk+oLnuFx/EQ7n/VwQCPlGO59oErv+xxP7nyoz+J/c/wADofxP9n/q/wB5+w5j5Sj9h8r9jyP0uj/A7jYp/GfA2LPyFnk9Dd4H2gIme6/3H+g/YfW/AOr+I+Up+A+Z9bTwfkfcHUj3vyvqfYdDuf6H9Z3NPqLn7H3T7Cz/AMz9xqfuNDwP/A4PyP8AU/8Am/nP7D5j/wCn/wBXm+do9RscF/2Pof4voPB+d8D+D/q0/rObc0I+UqeUU95778BT+o/+Hybzyv3/AAe4+xh3n/B/A8nA/SeB+A8vM9xPsPJnbvlOHnNzy3z9B85q/wDyeUa+VQ0eVgeU2+UAeU2f5PlQPunlmNj3n8LwP3NHwH+bZ/WfvftHvc+0p7P/oQ==";

        $immigrationReq = [
            'DocumentNo' => $request->session()->get('passportSecondaryVisitor'),
            'IssuingCountry' => trim($request->get('issuingCountry')),
            'RThumb' => $fingerDataR1,
            'RIndex' => $fingerDataR2,
            'RMiddle' => $fingerDataR3,
            'RRing' => $fingerDataR4,
            'RLittle' => $fingerDataR5,
            'LThumb' => $fingerDataL1,
            'LIndex' => $fingerDataL2,
            'LMiddle' => $fingerDataL3,
            'LRing' => $fingerDataL4,
            'LLittle' => $fingerDataL5
        ];

        $body = [
            'immigrationReq' => $immigrationReq,
            'Msisdn' => $request->session()->get('msisdnSecondaryVisitor'),
            'UserID' => $this->user['UserID'],
            'Platform' => 'web',
            'RegType' => 'New',
            'reasonCode' => $request->tcraReason,
        ];

        $url = 'VisitorNewSecondary';

        $data = $this->postRequest($url, $body);

        foreach ($immigrationReq as $key => $value) {
            if (in_array($value, $fingerArray) && ($value !== null)) {
                unset($key);
            }
        }

        Log::channel('Secondary-msisdn-visitor-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RegistrationStatusCode'] == 0 && $data['VerificationStatusCode'] == 0 && $data['TcraResponseCode'] == 150) {
            $request->session()->forget('msisdnSecondaryVisitor');
            $request->session()->forget('passportSecondaryVisitor');

            return response()
                ->json([
                    'message' => 'Registration successful !',
                    'status' => null
                ], 200);
        } elseif ($data['VerificationStatusCode'] !== 0) {
            return response()->json(['message' => 'Customer Biometric Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['TcraResponseCode'] == 151) {
            return response()->json([
                'message' => 'Customer NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 152) {

            return response()->json([
                'message' => 'Agent NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 153) {
            return response()->json([
                'message' => 'Customer has reached maximum SIM cards !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 154) {
            return response()->json([
                'message' => 'Customer reason not accepted by TCRA. Please choose another !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 156) {
            return response()->json([
                'message' => 'Duplicate customer msisdn from TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 80) {
            return response()
                ->json([
                    'message' => 'Error : Minor not allowed for this registration !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 90) {
            return response()
                ->json([
                    'message' => 'Customer Msisdn already exist !',
                    'status' => $data['RegStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 91) {
            return response()
                ->json([
                    'message' => 'Please wait for 30 mins before registering again !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 92) {
            return response()
                ->json([
                    'message' => 'Failed NIDA verification !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 93) {
            return response()
                ->json([
                    'message' => 'Error : Could not connect to NIDA !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 94) {
            return response()
                ->json([
                    'message' => 'Error: Immigration Connection Timed out !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 95) {
            return response()
                ->json([
                    'message' => 'Error: Failed to update iCAP !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } elseif ($data['RegistrationStatusCode'] == 999) {
            return response()
                ->json([
                    'message' => 'Error : General error !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => 'An error has occured !',
                    'status' => $data['RegistrationStatusCode']
                ], 400);
        }
    }


    public function registerMinorCheck(RegistrationRequest $request)
    {
        $body = [
            'MSISDN' => $request->msisdn,
            'UserID' => $this->user['UserID']
        ];

        $url = 'QRYKYC';

        $data = $this->postRequest($url, $body);

        Log::channel('Minor-check')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        //Customer is Bio-Registered
        if ($data['bioRegStatus'] === 'Y' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is already Biometrically registered. Thank you!'], 400);
        } //Customer is E-Registered not Bio-Registered
        elseif ($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is already registered, but NOT Bio-registered. Thank you!'], 400);
        } //Customer is New
        elseif (($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'NONE') || ($data['bioRegStatus'] === 'Y' && $data['RegistrationStatus'] === 'NONE')) {

            $bodyMinor = [
                'Msisdn' => $request->msisdn,
                'UserID' => $this->user['UserID'],
            ];

            $urlMinor = 'QRYKYM';

            $dataMinor = $this->postRequest($urlMinor, $bodyMinor);

            if ($dataMinor['RegistrationStatus'] == 'Not registered') {
                $request->session()->put('msisdnMinor', $request->msisdn);
                $request->session()->put('previous-route', Route::current()->getName());
                return response()->json(null, 200);
            } elseif ($dataMinor['RegistrationStatus'] == 'Registered') {

                return response()->json('This minor customer msisdn is already registered. Thank you!', 400);
            } else {
                return response()->json(['message' => 'Something went wrong while querying minor KYC !'], 400);
            }
        }

        return response()->json(['message' => 'Something went wrong. Please try again !'], 400);
    }

    public function registerMinor(RegistrationRequest $request)
    {
        if ($request->file('IDFile')) {
            $IDFile = file_get_contents($request->file('IDFile'));
            $IDFilebase64 = base64_encode($IDFile);
        } else {
            $IDFilebase64 = null;
        }

        if ($request->file('potraitFile')) {
            $potraitFile = file_get_contents($request->file('potraitFile'));
            $potraitFilebase64 = base64_encode($potraitFile);
        } else {
            $potraitFilebase64 = null;
        }

        $minorDOB = date('Y-m-d', strtotime(substr($request->minorDOB, 0, strpos($request->minorDOB, '('))));

        $dateTimestamp = strtotime($minorDOB);

        // $timestamp = now();

        // $totalDuration = $timestamp->diffForHumans($minorDOB);

        // return response()->json($totalDuration, 200);

        // $now = time(); // or your date as well
        // $datediff = $now - $dateTimestamp;

        // $years = $datediff / (60 * 60 * 24*365.25);

        // if($years <=18 && $years>=12) {
        //     return response()->json('Yes', 200);
        // }

        // return response()->json('No', 200);


        $body = [
            'ParentFingerCode' => $request->fingerCode,
            'ParentFingerData' => $request->fingerData,

            'ParentNIN' => $request->parentNIN,
            'MSISDN' => $request->session()->get('msisdnMinor'),
            'ParentMSISDN' => $request->parentMsisdn,
            'BirthcertificateNo' => $request->idNumber,
            'MinorPicture' => $potraitFilebase64,
            'BirthcertificateImage' => $IDFilebase64,

            'MinorFirstName' => $request->firstName,
            'MinorMiddleName' => $request->middleName,
            'MinorLastName' => $request->lastName,
            'Gender' => $request->minorGender,
            'MinorDob' => date('Y-m-d', strtotime(substr($request->minorDOB, 0, strpos($request->minorDOB, '(')))),

            'Platform' => 'web',
            'UserID' => $this->user['UserID'],
        ];

        $url = 'RegisterMinorNew';

        $data = $this->postRequest($url, $body);

        unset($body['ParentFingerData']);
        unset($body['MinorPicture']);
        unset($body['BirthcertificateImage']);

        Log::channel('Minor-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RegistrationStatusCode'] == 0 && $data['NidaErroCode'] == 0) {
            $request->session()->forget('msisdnMinor');

            return response()->json([
                'message' => 'Registration successful !',
                'status' => null
            ], 200);
        } elseif ($data['NidaErrorCode'] == 01) {
            return response()->json([
                'message' => 'Customer Biometric verification failed',
                'status' => $data['NidaErrorCode']
            ], 400);
        } elseif ($data['NidaErrorCode'] == 132) {
            return response()->json([
                'message' => 'Customer NIN not found',
                'status' => $data['NidaErrorCode']
            ], 400);
        } elseif ($data['NidaErrorCode'] == 141) {
            return response()->json([
                'message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !',
                'status' => $data['NidaErrorCode']
            ], 400);
        } elseif ($data['NidaErrorCode'] == 172) {
            return response()->json([
                'message' => 'Customer has defaced fingers. Thanks !',
                'status' => $data['NidaErrorCode']
            ], 400);
        } elseif ($data['NidaErrorCode'] !== 0) {
            return response()->json([
                'message' => $data['NidaErrorMessage'],
                'status' => $data['NidaErrorCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 90) {
            return response()->json([
                'message' => 'Customer Msisdn already exist !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 91) {
            return response()->json([
                'message' => 'Please wait for 30 mins before registering again !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 92) {
            return response()->json([
                'message' => 'Failed NIDA verification !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 93) {
            return response()->json([
                'message' => 'Error : Could not connect to NIDA !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 94) {
            return response()->json([
                'message' => 'Error: NIDA Connection Timed out !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 95) {
            return response()->json([
                'message' => 'Error: Failed to update iCAP !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        } elseif ($data['RegistrationStatusCode'] == 999) {
            return response()->json([
                'message' => 'Error : General error !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        } else {
            return response()->json([
                'message' => 'An error has occured !',
                'status' => $data['RegistrationStatusCode']
            ], 400);
        }
    }

    private function getRegistrationCode($name)
    {
        switch ($name) {
            case 'INDI':
                return 2000;
                break;
            case 'FORE':
                return 2020;
                break;
            case 'VISI':
                return 2030;
                break;
            case 'MINR':
                return 2040;
                break;
            case 'DIPL':
                return 2050;
                break;
            case 'DEFA':
                return 2060;
                break;

            default:
                # code...
                break;
        }
    }

    public function diplomatCheck(RegistrationRequest $request)
    {
        $body = [
            'CustomerIDNumber' => $request->passportNumber,
            'CustomerMsisdn' => $request->msisdn,
            'IDType' => 'P',
            'UserID' => $this->user['UserID'],
            "RegType" => 'DIPS'
        ];

        $url = 'IDNumberAndMsisdnCheck';

        $data = $this->postRequest($url, $body);

        Log::channel('New-msisdn-diplomat-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['blacklisted'] !== 0 || $data['BlacklistedReason'] !== null) {
            return response()->json(['message' => 'Customer Passport number is blacklisted with reason: ' . $data['BlacklistedReason']], 400);
        }
        if ($data['BioregStatus'] === 'Y' && $data['RegistrationStatus'] == 'REGISTERED') {
            return response()->json(['message' => 'Customer is biometrically registered '], 400);
        }

        //Customer is New
        elseif (($data['BioregStatus'] === 'N' && $data['RegistrationStatus'] === 'NONE') || ($data['BioregStatus'] === 'Y' && $data['RegistrationStatus'] === 'NONE') || ($data['BioregStatus'] === 'N' && $data['RegistrationStatus'] === 'REGISTERED')) {

            if (is_array($data['MsisdnStatusPerIDNumber'])) {
                foreach ($data['MsisdnStatusPerIDNumber'] as $key => $value) {

                    if ($value['TcraStatus'] == 'PRIMARY') {
                        $request->session()->put(['previous-route' => Route::current()->getName(), 'passportSecondaryDiplomat' => $request->passportNumber, 'msisdnSecondaryDiplomat' => $request->msisdn]);
                        return response()->json(['status' => 1], 200);
                    }
                }
                $request->session()->put(['previous-route' => Route::current()->getName(), 'passportPrimaryDiplomat' => $request->passportNumber, 'msisdnPrimaryDiplomat' => $request->msisdn]);
                return response()->json(['status' => 2], 200);
            } elseif ($data['MsisdnStatusPerIDNumber'] == null) {
                $request->session()->put(['previous-route' => Route::current()->getName(), 'passportPrimaryDiplomat' => $request->passportNumber, 'msisdnPrimaryDiplomat' => $request->msisdn]);
                return response()->json(['status' => 2], 200);
            }
        } elseif ($data['errorMsg'] !== null) {
            return response()->json(['message' => 'An error occured: ' . $data['errorMsg']], 400);
        } else {
            return response()->json(['message' => 'An error occured !', 'status' => $data], 400);
        }
    }

    public function diplomatRegisterPrimary(RegistrationRequest $request)
    {
        $IDFrontFile = file_get_contents($request->file('frontIDFile'));
        $IDFrontFilebase64 = base64_encode($IDFrontFile);

        $IDBackFile = file_get_contents($request->file('backIDFile'));
        $IDBackFilebase64 = base64_encode($IDBackFile);

        $PassportFile = file_get_contents($request->file('passportFile'));
        $PassportFilebase64 = base64_encode($PassportFile);

        $body = [
            'MSISDN' => $request->session()->get('msisdnPrimaryDiplomat'),
            'FirstName' => $request->firstName,
            'MiddleName' => $request->middleName,
            'Surname' => $request->lastName,
            'PassportNumber' => $request->session()->get('passportPrimaryDiplomat'),
            'IDNumber' => $request->get('idNumber'),
            'Gender' => $request->gender,
            'Institution' => $request->institution,
            'Dob' => date('Y-m-d', strtotime(substr($request->dob, 0, strpos($request->dob, '(')))),
            'Country' => $request->country,
            'FrontIDImage' => $IDFrontFilebase64,
            'BackIDImage' => $IDBackFilebase64,
            'PassportImage' => $PassportFilebase64,
            'UserID' => $this->user['UserID']
        ];

        $url = 'NewDiplomatPrimary';

        $data = $this->postRequest($url, $body);

        unset($body['FrontIDImage']);
        unset($body['BackIDImage']);
        unset($body['PassportImage']);

        Log::channel('Primary-msisdn-diplomat-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 0) {
            $request->session()->forget('msisdnPrimaryDiplomat');
            $request->session()->forget('passportPrimaryDiplomat');

            return response()
                ->json([
                    'message' => 'Successful Diplomat Registration !',
                    'status' => $data['ID']
                ], 200);
        }

        return response()
            ->json([
                'message' => 'Sorry, Something went wrong . Try again !',
            ], 400);
    }

    public function diplomatRegisterSecondary(RegistrationRequest $request)
    {
        $IDFrontFile = file_get_contents($request->file('frontIDFile'));
        $IDFrontFilebase64 = base64_encode($IDFrontFile);

        $IDBackFile = file_get_contents($request->file('backIDFile'));
        $IDBackFilebase64 = base64_encode($IDBackFile);

        $PassportFile = file_get_contents($request->file('passportFile'));
        $PassportFilebase64 = base64_encode($PassportFile);

        $body = [
            'MSISDN' => $request->session()->get('msisdnSecondaryDiplomat'),
            'FirstName' => $request->firstName,
            'MiddleName' => $request->middleName,
            'Surname' => $request->lastName,
            'PassportNumber' => $request->session()->get('passportSecondaryDiplomat'),
            'IDNumber' => $request->get('idNumber'),
            'Gender' => $request->gender,
            'Institution' => $request->institution,
            'Dob' => date('Y-m-d', strtotime(substr($request->dob, 0, strpos($request->dob, '(')))),
            'Country' => $request->country,
            'FrontIDImage' => $IDFrontFilebase64,
            'BackIDImage' => $IDBackFilebase64,
            'PassportImage' => $PassportFilebase64,
            'ReasonCode' => $request->tcraReason,
            'UserID' => $this->user['UserID']
        ];

        $url = 'NewDiplomatSecondary';

        $data = $this->postRequest($url, $body);

        unset($body['FrontIDImage']);
        unset($body['BackIDImage']);
        unset($body['PassportImage']);

        Log::channel('Secondary-msisdn-diplomat-register')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            $request->session()->forget('msisdnPrimaryDiplomat');
            $request->session()->forget('passportPrimaryDiplomat');
            return response()
                ->json([
                    'message' => 'Successful Diplomat Registration !',
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
                    'message' => 'Sorry, Something went wrong . Try again !',
                ], 400);
        }
    }

    public function deregNIDA(RegistrationRequest $request)
    {
        $body = [
            'NIN' => $request->NIN,
            'FingerCode' => $request->fingerCode,
            'Fingerprints' => $request->fingerData,
            'Msisdn' => $request->msisdn,
            'UserId' => $this->user['UserID'],
            'platform' => 'web'
        ];

        $url = 'Dereg';

        $data = $this->postRequest($url, $body);

        // return response()->json($data, 200);

        unset($body['Fingerprints']);

        Log::channel('De-Reg-Nida')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            $list = explode(',', $data['Description']);

            for ($i = 0; $i < count($list); $i++) {
                if ($list[$i] == $request->msisdn) {
                    unset($list[$i]);
                }
            }

            session()->put(['previous-route' => Route::current()->getName(), 'deregMsisdnList' => $list, 'DeregPrimaryMsisdn' => $request->get('msisdn')]);
            return response()
                ->json(null, 200);
        } elseif ($data['ID'] == 01) {
            return response()
                ->json([
                    'message' => 'Customer Biometric verification failed',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 132) {
            return response()
                ->json([
                    'message' => 'Customer NIN not found',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 141) {
            return response()
                ->json([
                    'message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 172) {
            return response()
                ->json([
                    'message' => 'Customer has defaced fingers. Thanks !',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 40) {
            return response()
                ->json([
                    'message' => 'Primary MSISDN ' . $request->msisdn . ' Is not among the List of MSISDNs registered With NIN !',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 41) {
            return response()
                ->json([
                    'message' => 'An Internal Error Occured while fetching customer MSISDNs from Icap !',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 42) {
            return response()
                ->json([
                    'message' => 'Customer MSISDNs not found with NIN ' . $request->NIN . ' !',
                    'status' => $data['Description']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => 'An error has occured !',
                    'status' => $data['Description']
                ], 400);
        }
    }

    public function getDeregMsisdn()
    {
        if (session::has('deregMsisdnList')) {
            return response()->json(session::get('deregMsisdnList'), 200);
        } else {
            return response()->json(null, 400);
        }
    }

    public function deRegMsisdn(RegistrationRequest $request)
    {
        $body = [
            'PrimaryMsisdn' => $request->session()->get('DeregPrimaryMsisdn'),
            'MsisdnList' =>  $request->deregMsisdn,
            'platform' => 'web',
            'UserID' => $this->user['UserID']
        ];

        $url = 'DeregMsisdn';

        $data = $this->postRequest($url, $body);

        //return response()->json($data, 200);

        Log::channel('De-Reg-Msisdn')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            session()->put(['previous-route' => Route::current()->getName()]);
            return response()->json(null, 200);
        } else {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['Description']
                ], 400);
        }

        return redirect()->back()->withErrors($data['Description'])->withInput();
    }

    public function deRegCode(RegistrationRequest $request)
    {
        $body = [
            'PrimaryMsisdn' => $request->session()->get('DeregPrimaryMsisdn'),
            'OTP' =>  $request->codeNumber,
            'Reason' => $request->deregReason
        ];

        $url = 'VerifyDeregOTP';

        $data = $this->postRequest($url, $body);

        Log::channel('De-Reg-Code')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {

            session::forget(['previous-route', 'deregMsisdnList', 'DeregPrimaryMsisdn']);
            return response()->json([
                'message' => 'Successful Customer Msisdn De-Registration !',
                'status' => $data['Description']
            ], 200);
        } elseif ($data['ID'] == 21) {
            return response()
                ->json([
                    'message' => 'Failed Customer Msisdn De-Registration !',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 23) {
            return response()
                ->json([
                    'message' => 'Invalid OTP !',
                    'status' => $data['Description']
                ], 400);
        } elseif ($data['ID'] == 22 || $data['ID'] == 24) {
            return response()
                ->json([
                    'message' => 'Error from iCAP. Please dial *106# to comfirm De-registration !',
                    'status' => $data['Description']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['Description']
                ], 400);
        }

        return redirect()->back()->withErrors($data['Description'])->withInput();
    }


    public function getRegions()
    {
        $url = 'Imsregions';

        return $this->getRequest($url);
    }

    public function getDistrict($Id)
    {
        $url = 'ImsDistrictByRegion/' . $Id;
        $territory = $this->getRequest($url);

        return $territory;
    }

    public function getWard($Id)
    {
        $url = 'GetWardsByDistrictId/' . $Id;
        $territory = $this->getRequest($url);

        return $territory;
    }

    public function getVillage($Id)
    {
        $url = 'GetVillageByWardID/' . $Id;
        $territory = $this->getRequest($url);

        return $territory;
    }

    public function getCountryList()
    {
        return  array(0 => array('Code' => 'AF', 'Name' => 'Afghanistan',), 1 => array('Code' => 'AX', 'Name' => 'Åland Islands',), 2 => array('Code' => 'AL', 'Name' => 'Albania',), 3 => array('Code' => 'DZ', 'Name' => 'Algeria',), 4 => array('Code' => 'AS', 'Name' => 'American Samoa',), 5 => array('Code' => 'AD', 'Name' => 'Andorra',), 6 => array('Code' => 'AO', 'Name' => 'Angola',), 7 => array('Code' => 'AI', 'Name' => 'Anguilla',), 8 => array('Code' => 'AQ', 'Name' => 'Antarctica',), 9 => array('Code' => 'AG', 'Name' => 'Antigua and Barbuda',), 10 => array('Code' => 'AR', 'Name' => 'Argentina',), 11 => array('Code' => 'AM', 'Name' => 'Armenia',), 12 => array('Code' => 'AW', 'Name' => 'Aruba',), 13 => array('Code' => 'AU', 'Name' => 'Australia',), 14 => array('Code' => 'AT', 'Name' => 'Austria',), 15 => array('Code' => 'AZ', 'Name' => 'Azerbaijan',), 16 => array('Code' => 'BS', 'Name' => 'Bahamas',), 17 => array('Code' => 'BH', 'Name' => 'Bahrain',), 18 => array('Code' => 'BD', 'Name' => 'Bangladesh',), 19 => array('Code' => 'BB', 'Name' => 'Barbados',), 20 => array('Code' => 'BY', 'Name' => 'Belarus',), 21 => array('Code' => 'BE', 'Name' => 'Belgium',), 22 => array('Code' => 'BZ', 'Name' => 'Belize',), 23 => array('Code' => 'BJ', 'Name' => 'Benin',), 24 => array('Code' => 'BM', 'Name' => 'Bermuda',), 25 => array('Code' => 'BT', 'Name' => 'Bhutan',), 26 => array('Code' => 'BO', 'Name' => 'Bolivia, Plurinational State of',), 27 => array('Code' => 'BQ', 'Name' => 'Bonaire, Sint Eustatius and Saba',), 28 => array('Code' => 'BA', 'Name' => 'Bosnia and Herzegovina',), 29 => array('Code' => 'BW', 'Name' => 'Botswana',), 30 => array('Code' => 'BV', 'Name' => 'Bouvet Island',), 31 => array('Code' => 'BR', 'Name' => 'Brazil',), 32 => array('Code' => 'IO', 'Name' => 'British Indian Ocean Territory',), 33 => array('Code' => 'BN', 'Name' => 'Brunei Darussalam',), 34 => array('Code' => 'BG', 'Name' => 'Bulgaria',), 35 => array('Code' => 'BF', 'Name' => 'Burkina Faso',), 36 => array('Code' => 'BI', 'Name' => 'Burundi',), 37 => array('Code' => 'KH', 'Name' => 'Cambodia',), 38 => array('Code' => 'CM', 'Name' => 'Cameroon',), 39 => array('Code' => 'CA', 'Name' => 'Canada',), 40 => array('Code' => 'CV', 'Name' => 'Cape Verde',), 41 => array('Code' => 'KY', 'Name' => 'Cayman Islands',), 42 => array('Code' => 'CF', 'Name' => 'Central African Republic',), 43 => array('Code' => 'TD', 'Name' => 'Chad',), 44 => array('Code' => 'CL', 'Name' => 'Chile',), 45 => array('Code' => 'CN', 'Name' => 'China',), 46 => array('Code' => 'CX', 'Name' => 'Christmas Island',), 47 => array('Code' => 'CC', 'Name' => 'Cocos (Keeling) Islands',), 48 => array('Code' => 'CO', 'Name' => 'Colombia',), 49 => array('Code' => 'KM', 'Name' => 'Comoros',), 50 => array('Code' => 'CG', 'Name' => 'Congo',), 51 => array('Code' => 'CD', 'Name' => 'Congo, the Democratic Republic of the',), 52 => array('Code' => 'CK', 'Name' => 'Cook Islands',), 53 => array('Code' => 'CR', 'Name' => 'Costa Rica',), 54 => array('Code' => 'CI', 'Name' => 'Côte d\'Ivoire',), 55 => array('Code' => 'HR', 'Name' => 'Croatia',), 56 => array('Code' => 'CU', 'Name' => 'Cuba',), 57 => array('Code' => 'CW', 'Name' => 'Curaçao',), 58 => array('Code' => 'CY', 'Name' => 'Cyprus',), 59 => array('Code' => 'CZ', 'Name' => 'Czech Republic',), 60 => array('Code' => 'DK', 'Name' => 'Denmark',), 61 => array('Code' => 'DJ', 'Name' => 'Djibouti',), 62 => array('Code' => 'DM', 'Name' => 'Dominica',), 63 => array('Code' => 'DO', 'Name' => 'Dominican Republic',), 64 => array('Code' => 'EC', 'Name' => 'Ecuador',), 65 => array('Code' => 'EG', 'Name' => 'Egypt',), 66 => array('Code' => 'SV', 'Name' => 'El Salvador',), 67 => array('Code' => 'GQ', 'Name' => 'Equatorial Guinea',), 68 => array('Code' => 'ER', 'Name' => 'Eritrea',), 69 => array('Code' => 'EE', 'Name' => 'Estonia',), 70 => array('Code' => 'ET', 'Name' => 'Ethiopia',), 71 => array('Code' => 'FK', 'Name' => 'Falkland Islands (Malvinas)',), 72 => array('Code' => 'FO', 'Name' => 'Faroe Islands',), 73 => array('Code' => 'FJ', 'Name' => 'Fiji',), 74 => array('Code' => 'FI', 'Name' => 'Finland',), 75 => array('Code' => 'FR', 'Name' => 'France',), 76 => array('Code' => 'GF', 'Name' => 'French Guiana',), 77 => array('Code' => 'PF', 'Name' => 'French Polynesia',), 78 => array('Code' => 'TF', 'Name' => 'French Southern Territories',), 79 => array('Code' => 'GA', 'Name' => 'Gabon',), 80 => array('Code' => 'GM', 'Name' => 'Gambia',), 81 => array('Code' => 'GE', 'Name' => 'Georgia',), 82 => array('Code' => 'DE', 'Name' => 'Germany',), 83 => array('Code' => 'GH', 'Name' => 'Ghana',), 84 => array('Code' => 'GI', 'Name' => 'Gibraltar',), 85 => array('Code' => 'GR', 'Name' => 'Greece',), 86 => array('Code' => 'GL', 'Name' => 'Greenland',), 87 => array('Code' => 'GD', 'Name' => 'Grenada',), 88 => array('Code' => 'GP', 'Name' => 'Guadeloupe',), 89 => array('Code' => 'GU', 'Name' => 'Guam',), 90 => array('Code' => 'GT', 'Name' => 'Guatemala',), 91 => array('Code' => 'GG', 'Name' => 'Guernsey',), 92 => array('Code' => 'GN', 'Name' => 'Guinea',), 93 => array('Code' => 'GW', 'Name' => 'Guinea-Bissau',), 94 => array('Code' => 'GY', 'Name' => 'Guyana',), 95 => array('Code' => 'HT', 'Name' => 'Haiti',), 96 => array('Code' => 'HM', 'Name' => 'Heard Island and McDonald Islands',), 97 => array('Code' => 'VA', 'Name' => 'Holy See (Vatican City State)',), 98 => array('Code' => 'HN', 'Name' => 'Honduras',), 99 => array('Code' => 'HK', 'Name' => 'Hong Kong',), 100 => array('Code' => 'HU', 'Name' => 'Hungary',), 101 => array('Code' => 'IS', 'Name' => 'Iceland',), 102 => array('Code' => 'IN', 'Name' => 'India',), 103 => array('Code' => 'ID', 'Name' => 'Indonesia',), 104 => array('Code' => 'IR', 'Name' => 'Iran, Islamic Republic of',), 105 => array('Code' => 'IQ', 'Name' => 'Iraq',), 106 => array('Code' => 'IE', 'Name' => 'Ireland',), 107 => array('Code' => 'IM', 'Name' => 'Isle of Man',), 108 => array('Code' => 'IL', 'Name' => 'Israel',), 109 => array('Code' => 'IT', 'Name' => 'Italy',), 110 => array('Code' => 'JM', 'Name' => 'Jamaica',), 111 => array('Code' => 'JP', 'Name' => 'Japan',), 112 => array('Code' => 'JE', 'Name' => 'Jersey',), 113 => array('Code' => 'JO', 'Name' => 'Jordan',), 114 => array('Code' => 'KZ', 'Name' => 'Kazakhstan',), 115 => array('Code' => 'KE', 'Name' => 'Kenya',), 116 => array('Code' => 'KI', 'Name' => 'Kiribati',), 117 => array('Code' => 'KP', 'Name' => 'Korea, Democratic People\'s Republic of',), 118 => array('Code' => 'KR', 'Name' => 'Korea, Republic of',), 119 => array('Code' => 'KW', 'Name' => 'Kuwait',), 120 => array('Code' => 'KG', 'Name' => 'Kyrgyzstan',), 121 => array('Code' => 'LA', 'Name' => 'Lao People\'s Democratic Republic',), 122 => array('Code' => 'LV', 'Name' => 'Latvia',), 123 => array('Code' => 'LB', 'Name' => 'Lebanon',), 124 => array('Code' => 'LS', 'Name' => 'Lesotho',), 125 => array('Code' => 'LR', 'Name' => 'Liberia',), 126 => array('Code' => 'LY', 'Name' => 'Libya',), 127 => array('Code' => 'LI', 'Name' => 'Liechtenstein',), 128 => array('Code' => 'LT', 'Name' => 'Lithuania',), 129 => array('Code' => 'LU', 'Name' => 'Luxembourg',), 130 => array('Code' => 'MO', 'Name' => 'Macao',), 131 => array('Code' => 'MK', 'Name' => 'Macedonia, the Former Yugoslav Republic of',), 132 => array('Code' => 'MG', 'Name' => 'Madagascar',), 133 => array('Code' => 'MW', 'Name' => 'Malawi',), 134 => array('Code' => 'MY', 'Name' => 'Malaysia',), 135 => array('Code' => 'MV', 'Name' => 'Maldives',), 136 => array('Code' => 'ML', 'Name' => 'Mali',), 137 => array('Code' => 'MT', 'Name' => 'Malta',), 138 => array('Code' => 'MH', 'Name' => 'Marshall Islands',), 139 => array('Code' => 'MQ', 'Name' => 'Martinique',), 140 => array('Code' => 'MR', 'Name' => 'Mauritania',), 141 => array('Code' => 'MU', 'Name' => 'Mauritius',), 142 => array('Code' => 'YT', 'Name' => 'Mayotte',), 143 => array('Code' => 'MX', 'Name' => 'Mexico',), 144 => array('Code' => 'FM', 'Name' => 'Micronesia, Federated States of',), 145 => array('Code' => 'MD', 'Name' => 'Moldova, Republic of',), 146 => array('Code' => 'MC', 'Name' => 'Monaco',), 147 => array('Code' => 'MN', 'Name' => 'Mongolia',), 148 => array('Code' => 'ME', 'Name' => 'Montenegro',), 149 => array('Code' => 'MS', 'Name' => 'Montserrat',), 150 => array('Code' => 'MA', 'Name' => 'Morocco',), 151 => array('Code' => 'MZ', 'Name' => 'Mozambique',), 152 => array('Code' => 'MM', 'Name' => 'Myanmar',), 153 => array('Code' => 'NA', 'Name' => 'Namibia',), 154 => array('Code' => 'NR', 'Name' => 'Nauru',), 155 => array('Code' => 'NP', 'Name' => 'Nepal',), 156 => array('Code' => 'NL', 'Name' => 'Netherlands',), 157 => array('Code' => 'NC', 'Name' => 'New Caledonia',), 158 => array('Code' => 'NZ', 'Name' => 'New Zealand',), 159 => array('Code' => 'NI', 'Name' => 'Nicaragua',), 160 => array('Code' => 'NE', 'Name' => 'Niger',), 161 => array('Code' => 'NG', 'Name' => 'Nigeria',), 162 => array('Code' => 'NU', 'Name' => 'Niue',), 163 => array('Code' => 'NF', 'Name' => 'Norfolk Island',), 164 => array('Code' => 'MP', 'Name' => 'Northern Mariana Islands',), 165 => array('Code' => 'NO', 'Name' => 'Norway',), 166 => array('Code' => 'OM', 'Name' => 'Oman',), 167 => array('Code' => 'PK', 'Name' => 'Pakistan',), 168 => array('Code' => 'PW', 'Name' => 'Palau',), 169 => array('Code' => 'PS', 'Name' => 'Palestine, State of',), 170 => array('Code' => 'PA', 'Name' => 'Panama',), 171 => array('Code' => 'PG', 'Name' => 'Papua New Guinea',), 172 => array('Code' => 'PY', 'Name' => 'Paraguay',), 173 => array('Code' => 'PE', 'Name' => 'Peru',), 174 => array('Code' => 'PH', 'Name' => 'Philippines',), 175 => array('Code' => 'PN', 'Name' => 'Pitcairn',), 176 => array('Code' => 'PL', 'Name' => 'Poland',), 177 => array('Code' => 'PT', 'Name' => 'Portugal',), 178 => array('Code' => 'PR', 'Name' => 'Puerto Rico',), 179 => array('Code' => 'QA', 'Name' => 'Qatar',), 180 => array('Code' => 'RE', 'Name' => 'Réunion',), 181 => array('Code' => 'RO', 'Name' => 'Romania',), 182 => array('Code' => 'RU', 'Name' => 'Russian Federation',), 183 => array('Code' => 'RW', 'Name' => 'Rwanda',), 184 => array('Code' => 'BL', 'Name' => 'Saint Barthélemy',), 185 => array('Code' => 'SH', 'Name' => 'Saint Helena, Ascension and Tristan da Cunha',), 186 => array('Code' => 'KN', 'Name' => 'Saint Kitts and Nevis',), 187 => array('Code' => 'LC', 'Name' => 'Saint Lucia',), 188 => array('Code' => 'MF', 'Name' => 'Saint Martin (French part)',), 189 => array('Code' => 'PM', 'Name' => 'Saint Pierre and Miquelon',), 190 => array('Code' => 'VC', 'Name' => 'Saint Vincent and the Grenadines',), 191 => array('Code' => 'WS', 'Name' => 'Samoa',), 192 => array('Code' => 'SM', 'Name' => 'San Marino',), 193 => array('Code' => 'ST', 'Name' => 'Sao Tome and Principe',), 194 => array('Code' => 'SA', 'Name' => 'Saudi Arabia',), 195 => array('Code' => 'SN', 'Name' => 'Senegal',), 196 => array('Code' => 'RS', 'Name' => 'Serbia',), 197 => array('Code' => 'SC', 'Name' => 'Seychelles',), 198 => array('Code' => 'SL', 'Name' => 'Sierra Leone',), 199 => array('Code' => 'SG', 'Name' => 'Singapore',), 200 => array('Code' => 'SX', 'Name' => 'Sint Maarten (Dutch part)',), 201 => array('Code' => 'SK', 'Name' => 'Slovakia',), 202 => array('Code' => 'SI', 'Name' => 'Slovenia',), 203 => array('Code' => 'SB', 'Name' => 'Solomon Islands',), 204 => array('Code' => 'SO', 'Name' => 'Somalia',), 205 => array('Code' => 'ZA', 'Name' => 'South Africa',), 206 => array('Code' => 'GS', 'Name' => 'South Georgia and the South Sandwich Islands',), 207 => array('Code' => 'SS', 'Name' => 'South Sudan',), 208 => array('Code' => 'ES', 'Name' => 'Spain',), 209 => array('Code' => 'LK', 'Name' => 'Sri Lanka',), 210 => array('Code' => 'SD', 'Name' => 'Sudan',), 211 => array('Code' => 'SR', 'Name' => 'Suriname',), 212 => array('Code' => 'SJ', 'Name' => 'Svalbard and Jan Mayen',), 213 => array('Code' => 'SZ', 'Name' => 'Swaziland',), 214 => array('Code' => 'SE', 'Name' => 'Sweden',), 215 => array('Code' => 'CH', 'Name' => 'Switzerland',), 216 => array('Code' => 'SY', 'Name' => 'Syrian Arab Republic',), 217 => array('Code' => 'TW', 'Name' => 'Taiwan, Province of China',), 218 => array('Code' => 'TJ', 'Name' => 'Tajikistan',), 219 => array('Code' => 'TZ', 'Name' => 'Tanzania, United Republic of',), 220 => array('Code' => 'TH', 'Name' => 'Thailand',), 221 => array('Code' => 'TL', 'Name' => 'Timor-Leste',), 222 => array('Code' => 'TG', 'Name' => 'Togo',), 223 => array('Code' => 'TK', 'Name' => 'Tokelau',), 224 => array('Code' => 'TO', 'Name' => 'Tonga',), 225 => array('Code' => 'TT', 'Name' => 'Trinidad and Tobago',), 226 => array('Code' => 'TN', 'Name' => 'Tunisia',), 227 => array('Code' => 'TR', 'Name' => 'Turkey',), 228 => array('Code' => 'TM', 'Name' => 'Turkmenistan',), 229 => array('Code' => 'TC', 'Name' => 'Turks and Caicos Islands',), 230 => array('Code' => 'TV', 'Name' => 'Tuvalu',), 231 => array('Code' => 'UG', 'Name' => 'Uganda',), 232 => array('Code' => 'UA', 'Name' => 'Ukraine',), 233 => array('Code' => 'AE', 'Name' => 'United Arab Emirates',), 234 => array('Code' => 'GB', 'Name' => 'United Kingdom',), 235 => array('Code' => 'US', 'Name' => 'United States',), 236 => array('Code' => 'UM', 'Name' => 'United States Minor Outlying Islands',), 237 => array('Code' => 'UY', 'Name' => 'Uruguay',), 238 => array('Code' => 'UZ', 'Name' => 'Uzbekistan',), 239 => array('Code' => 'VU', 'Name' => 'Vanuatu',), 240 => array('Code' => 'VE', 'Name' => 'Venezuela, Bolivarian Republic of',), 241 => array('Code' => 'VN', 'Name' => 'Viet Nam',), 242 => array('Code' => 'VG', 'Name' => 'Virgin Islands, British',), 243 => array('Code' => 'VI', 'Name' => 'Virgin Islands, U.S.',), 244 => array('Code' => 'WF', 'Name' => 'Wallis and Futuna',), 245 => array('Code' => 'EH', 'Name' => 'Western Sahara',), 246 => array('Code' => 'YE', 'Name' => 'Yemen',), 247 => array('Code' => 'ZM', 'Name' => 'Zambia',), 248 => array('Code' => 'ZW', 'Name' => 'Zimbabwe',),);
    }

    public function ImmigrationCountryList()
    {
        return [
            ['COUNTRY' => 'AFGHANISTAN', 'ABBREVIATION' => 'AFG'], ['COUNTRY' => 'ALBANIA', 'ABBREVIATION' => 'ALB'], ['COUNTRY' => 'ALGERIA', 'ABBREVIATION' => 'DZA'], ['COUNTRY' => 'AMERICANSAMOA', 'ABBREVIATION' => 'ASM'], ['COUNTRY' => 'ANDORRA', 'ABBREVIATION' => 'AND'], ['COUNTRY' => 'ANGOLA', 'ABBREVIATION' => 'AGO'], ['COUNTRY' => 'ANGUILLA', 'ABBREVIATION' => 'AIA'], ['COUNTRY' => 'ANTARTICA', 'ABBREVIATION' => 'ATA'], ['COUNTRY' => 'ANTIGUAANDBARBUDA', 'ABBREVIATION' => 'ATG'], ['COUNTRY' => 'ARGENTINA', 'ABBREVIATION' => 'ARG'], ['COUNTRY' => 'ARMENIA', 'ABBREVIATION' => 'ARM'], ['COUNTRY' => 'ARUBA', 'ABBREVIATION' => 'ABW'], ['COUNTRY' => 'AUSTRALIA', 'ABBREVIATION' => 'AUS'], ['COUNTRY' => 'AUSTRIA', 'ABBREVIATION' => 'AUT'], ['COUNTRY' => 'AZERBAIJAN', 'ABBREVIATION' => 'AZE'], ['COUNTRY' => 'BAHAMAS', 'ABBREVIATION' => 'BHS'], ['COUNTRY' => 'BAHRAIN', 'ABBREVIATION' => 'BHR'], ['COUNTRY' => 'BANGLADESH', 'ABBREVIATION' => 'BGD'], ['COUNTRY' => 'BARBADOS', 'ABBREVIATION' => 'BRB'], ['COUNTRY' => 'BELARUS', 'ABBREVIATION' => 'BLR'], ['COUNTRY' => 'BELGIUM', 'ABBREVIATION' => 'BEL'], ['COUNTRY' => 'BELIZE', 'ABBREVIATION' => 'BLZ'], ['COUNTRY' => 'BENIN', 'ABBREVIATION' => 'BEN'], ['COUNTRY' => 'BERMUDA', 'ABBREVIATION' => 'BMU'], ['COUNTRY' => 'BHUTAN', 'ABBREVIATION' => 'BTN'], ['COUNTRY' => 'BOLIVIA', 'ABBREVIATION' => 'BOL'], ['COUNTRY' => 'BOSNIAANDHERZEGOWINA', 'ABBREVIATION' => 'BIH'], ['COUNTRY' => 'BOTSWANA', 'ABBREVIATION' => 'BWA'], ['COUNTRY' => 'BOUVETISLAND', 'ABBREVIATION' => 'BVT'], ['COUNTRY' => 'BRAZIL', 'ABBREVIATION' => 'BRA'], ['COUNTRY' => 'BRITISHINDIANOCEANTERRITORY', 'ABBREVIATION' => 'IOT'], ['COUNTRY' => 'BRUNEIDARUSSALAM', 'ABBREVIATION' => 'BRN'], ['COUNTRY' => 'BULGARIA', 'ABBREVIATION' => 'BGR'], ['COUNTRY' => 'BURKINAFASO', 'ABBREVIATION' => 'BFA'], ['COUNTRY' => 'BURUNDI', 'ABBREVIATION' => 'BDI'], ['COUNTRY' => 'CAMBODIA', 'ABBREVIATION' => 'KHM'], ['COUNTRY' => 'CAMEROON', 'ABBREVIATION' => 'CMR'], ['COUNTRY' => 'CANADA', 'ABBREVIATION' => 'CAN'], ['COUNTRY' => 'CAPEVERDE', 'ABBREVIATION' => 'CPV'], ['COUNTRY' => 'CAYMANISLANDS', 'ABBREVIATION' => 'CYM'], ['COUNTRY' => 'CENTRALAFRICANREPUBLIC', 'ABBREVIATION' => 'CAF'], ['COUNTRY' => 'CHAD', 'ABBREVIATION' => 'TCD'], ['COUNTRY' => 'CHILE', 'ABBREVIATION' => 'CHL'], ['COUNTRY' => 'CHINA', 'ABBREVIATION' => 'CHN'], ['COUNTRY' => 'CHRISTMASISLAND', 'ABBREVIATION' => 'CXR'], ['COUNTRY' => 'COCOS(KEELING)ISLANDS', 'ABBREVIATION' => 'CCK'], ['COUNTRY' => 'COLOMBIA', 'ABBREVIATION' => 'COL'], ['COUNTRY' => 'COMOROS', 'ABBREVIATION' => 'COM'], ['COUNTRY' => 'CONGODEMOCRATICREPUBLIC(ZAIRE)', 'ABBREVIATION' => 'COD',], ['COUNTRY' => 'CONGOPEOPLE\'SREPUBLIC', 'ABBREVIATION' => 'COG'], ['COUNTRY' => 'COOKISLANDS', 'ABBREVIATION' => 'COK'], ['COUNTRY' => 'COSTARICA', 'ABBREVIATION' => 'CRI'], ['COUNTRY' => 'COTED\'IVOIRE', 'ABBREVIATION' => 'CIV'], ['COUNTRY' => 'CROATIA(HRVATSKA)', 'ABBREVIATION' => 'HRV'], ['COUNTRY' => 'CUBA', 'ABBREVIATION' => 'CUB'], ['COUNTRY' => 'CYPRUS', 'ABBREVIATION' => 'CYP'], ['COUNTRY' => 'CZECHREPUBLIC', 'ABBREVIATION' => 'CZE'], ['COUNTRY' => 'DENMARK', 'ABBREVIATION' => 'DNK'], ['COUNTRY' => 'DJIBOUTI', 'ABBREVIATION' => 'DJI'], ['COUNTRY' => 'DOMINICA', 'ABBREVIATION' => 'DMA'], ['COUNTRY' => 'DOMINICANREPUBLIC', 'ABBREVIATION' => 'DOM'], ['COUNTRY' => 'EASTTIMOR', 'ABBREVIATION' => 'TLS'], ['COUNTRY' => 'ECUADOR', 'ABBREVIATION' => 'ECU'], ['COUNTRY' => 'EGYPT', 'ABBREVIATION' => 'EGY'], ['COUNTRY' => 'ELSALVADOR', 'ABBREVIATION' => 'SLV'], ['COUNTRY' => 'EQUATORIALGUINEA', 'ABBREVIATION' => 'GNQ'], ['COUNTRY' => 'ERITREA', 'ABBREVIATION' => 'ERI'], ['COUNTRY' => 'ESTONIA', 'ABBREVIATION' => 'EST'], ['COUNTRY' => 'ETHIOPIA', 'ABBREVIATION' => 'ETH'], ['COUNTRY' => 'FALKLANDISLANDS(MALVINAS)', 'ABBREVIATION' => 'FLK'], ['COUNTRY' => 'FAROEISLANDS', 'ABBREVIATION' => 'FRO'], ['COUNTRY' => 'FIJI', 'ABBREVIATION' => 'FJI'], ['COUNTRY' => 'FINLAND', 'ABBREVIATION' => 'FIN'], ['COUNTRY' => 'FRANCE', 'ABBREVIATION' => 'FRA'], ['COUNTRY' => 'FRENCHGUIANA', 'ABBREVIATION' => 'GUF'], ['COUNTRY' => 'FRENCHPOLYNESIA', 'ABBREVIATION' => 'PYF'], ['COUNTRY' => 'FRENCHSOUTHERNANDANTARCTICLANDS', 'ABBREVIATION' => 'ATF'], ['COUNTRY' => 'GABON', 'ABBREVIATION' => 'GAB'], ['COUNTRY' => 'GAMBIA', 'ABBREVIATION' => 'GMB'], ['COUNTRY' => 'GEORGIA', 'ABBREVIATION' => 'GEO'], ['COUNTRY' => 'GERMANY', 'ABBREVIATION' => 'DEU'], ['COUNTRY' => 'GHANA', 'ABBREVIATION' => 'GHA'], ['COUNTRY' => 'GIBRALTAR', 'ABBREVIATION' => 'GIB'], ['COUNTRY' => 'GREECE', 'ABBREVIATION' => 'GRC'], ['COUNTRY' => 'GREENLAND', 'ABBREVIATION' => 'GRL'], ['COUNTRY' => 'GRENADA', 'ABBREVIATION' => 'GRD'], ['COUNTRY' => 'GUADELOUPE', 'ABBREVIATION' => 'GLP'], ['COUNTRY' => 'GUAM', 'ABBREVIATION' => 'GUM'], ['COUNTRY' => 'GUATEMALA', 'ABBREVIATION' => 'GTM'], ['COUNTRY' => 'GUERNSEY', 'ABBREVIATION' => 'GGY'], ['COUNTRY' => 'GUINEA', 'ABBREVIATION' => 'GIN'], ['COUNTRY' => 'GUINEA-BISSAU', 'ABBREVIATION' => 'GNB'], ['COUNTRY' => 'GUYANA', 'ABBREVIATION' => 'GUY'], ['COUNTRY' => 'HAITI', 'ABBREVIATION' => 'HTI'], ['COUNTRY' => 'HEARDANDMCDONALDISLANDS', 'ABBREVIATION' => 'HMD'], ['COUNTRY' => 'HOLYSEE(VATICANCITYSTATE)', 'ABBREVIATION' => 'VAT'], ['COUNTRY' => 'HONDURAS', 'ABBREVIATION' => 'HND'], ['COUNTRY' => 'HONGKONG', 'ABBREVIATION' => 'HKG'], ['COUNTRY' => 'HUNGARY', 'ABBREVIATION' => 'HUN'], ['COUNTRY' => 'ICELAND', 'ABBREVIATION' => 'ISL'], ['COUNTRY' => 'INDIA', 'ABBREVIATION' => 'IND'], ['COUNTRY' => 'INDONESIA', 'ABBREVIATION' => 'IDN'], ['COUNTRY' => 'IRAN(ISLAMICREPUBLIC)', 'ABBREVIATION' => 'IRN'], ['COUNTRY' => 'IRAQ', 'ABBREVIATION' => 'IRQ'], ['COUNTRY' => 'IRELAND', 'ABBREVIATION' => 'IRL'], ['COUNTRY' => 'ISRAEL', 'ABBREVIATION' => 'ISR'], ['COUNTRY' => 'ITALY', 'ABBREVIATION' => 'ITA'], ['COUNTRY' => 'JAMAICA', 'ABBREVIATION' => 'JAM'], ['COUNTRY' => 'JAPAN', 'ABBREVIATION' => 'JPN'], ['COUNTRY' => 'JERSEY', 'ABBREVIATION' => 'JEY'], ['COUNTRY' => 'JORDAN', 'ABBREVIATION' => 'JOR'], ['COUNTRY' => 'KAZAKHSTAN', 'ABBREVIATION' => 'KAZ'], ['COUNTRY' => 'KENYA', 'ABBREVIATION' => 'KEN'], ['COUNTRY' => 'KIRIBATI', 'ABBREVIATION' => 'KIR'], ['COUNTRY' => 'KOREADEMOCRATICPEOPLE\'SREPUBLIC', 'ABBREVIATION' => 'PRK',], ['COUNTRY' => 'KOREA,REPUBLICOF', 'ABBREVIATION' => 'KOR',], ['COUNTRY' => 'KUWAIT', 'ABBREVIATION' => 'KWT'], ['COUNTRY' => 'KYRGYZSTAN', 'ABBREVIATION' => 'KGZ'], ['COUNTRY' => 'LAOPEOPLE\'SDEMOCRATICREPUBLIC', 'ABBREVIATION' => 'LAO'], ['COUNTRY' => 'LATVIA', 'ABBREVIATION' => 'LVA'], ['COUNTRY' => 'LEBANON', 'ABBREVIATION' => 'LBN'], ['COUNTRY' => 'LESOTHO', 'ABBREVIATION' => 'LSO'], ['COUNTRY' => 'LIBERIA', 'ABBREVIATION' => 'LBR'], ['COUNTRY' => 'LIBYANARABJAMAHIRIYA', 'ABBREVIATION' => 'LBY'], ['COUNTRY' => 'LIECHTENSTEIN', 'ABBREVIATION' => 'LIE'], ['COUNTRY' => 'LITHUANIA', 'ABBREVIATION' => 'LTU'], ['COUNTRY' => 'LUXEMBOURG', 'ABBREVIATION' => 'LUX'], ['COUNTRY' => 'MACAU', 'ABBREVIATION' => 'MAC'], ['COUNTRY' => 'MACEDONIAFORMERYUGOSLAVREPUBLIC', 'ABBREVIATION' => 'MKD',], ['COUNTRY' => 'MADAGASCAR', 'ABBREVIATION' => 'MDG'], ['COUNTRY' => 'MALAWI', 'ABBREVIATION' => 'MWI'], ['COUNTRY' => 'MALAYSIA', 'ABBREVIATION' => 'MYS'], ['COUNTRY' => 'MALDIVES', 'ABBREVIATION' => 'MDV'], ['COUNTRY' => 'MALI', 'ABBREVIATION' => 'MLI'], ['COUNTRY' => 'MALTA', 'ABBREVIATION' => 'MLT'], ['COUNTRY' => 'MAN,ISLEOF', 'ABBREVIATION' => 'IMN',], ['COUNTRY' => 'MARSHALLISLANDS', 'ABBREVIATION' => 'MHL'], ['COUNTRY' => 'MARTINIQUE', 'ABBREVIATION' => 'MTQ'], ['COUNTRY' => 'MAURITANIA', 'ABBREVIATION' => 'MRT'], ['COUNTRY' => 'MAURITIUS', 'ABBREVIATION' => 'MUS'], ['COUNTRY' => 'MAYOTTE', 'ABBREVIATION' => 'MYT'], ['COUNTRY' => 'MEXICO', 'ABBREVIATION' => 'MEX'], ['COUNTRY' => 'MICRONESIA,FEDERATEDSTATES', 'ABBREVIATION' => 'FSM',], ['COUNTRY' => 'MOLDOVAREPUBLIC', 'ABBREVIATION' => 'MDA',], ['COUNTRY' => 'MONACO', 'ABBREVIATION' => 'MCO'], ['COUNTRY' => 'MONGOLIA', 'ABBREVIATION' => 'MNG'], ['COUNTRY' => 'MONTENEGRO', 'ABBREVIATION' => 'MNE'], ['COUNTRY' => 'MONTSERRAT', 'ABBREVIATION' => 'MSR'], ['COUNTRY' => 'MOROCCO', 'ABBREVIATION' => 'MAR'], ['COUNTRY' => 'MOZAMBIQUE', 'ABBREVIATION' => 'MOZ'], ['COUNTRY' => 'MYANMAR', 'ABBREVIATION' => 'MMR'], ['COUNTRY' => 'NAMIBIA', 'ABBREVIATION' => 'NAM'], ['COUNTRY' => 'NAURU', 'ABBREVIATION' => 'NRU'], ['COUNTRY' => 'NEPAL', 'ABBREVIATION' => 'NPL'], ['COUNTRY' => 'NETHERLANDS', 'ABBREVIATION' => 'NLD'], ['COUNTRY' => 'NETHERLANDSANTILLES', 'ABBREVIATION' => 'ANT'], ['COUNTRY' => 'NEWCALEDONIA', 'ABBREVIATION' => 'NCL'], ['COUNTRY' => 'NEWZEALAND', 'ABBREVIATION' => 'NZL'], ['COUNTRY' => 'NICARAGUA', 'ABBREVIATION' => 'NIC'], ['COUNTRY' => 'NIGER', 'ABBREVIATION' => 'NER'], ['COUNTRY' => 'NIGERIA', 'ABBREVIATION' => 'NGA'], ['COUNTRY' => 'NIUE', 'ABBREVIATION' => 'NIU'], ['COUNTRY' => 'NORFOLKISLAND', 'ABBREVIATION' => 'NFK'], ['COUNTRY' => 'NORTHERNMARIANAISLANDS', 'ABBREVIATION' => 'MNP'], ['COUNTRY' => 'NORWAY', 'ABBREVIATION' => 'NOR'], ['COUNTRY' => 'OMAN', 'ABBREVIATION' => 'OMN'], ['COUNTRY' => 'PAKISTAN', 'ABBREVIATION' => 'PAK'], ['COUNTRY' => 'PALAU', 'ABBREVIATION' => 'PLW'], ['COUNTRY' => 'PALESTINIANOCCUPIEDTERRITORY', 'ABBREVIATION' => 'PSE',], ['COUNTRY' => 'PANAMA', 'ABBREVIATION' => 'PAN'], ['COUNTRY' => 'PAPUANEWGUINEA', 'ABBREVIATION' => 'PNG'], ['COUNTRY' => 'PARAGUAY', 'ABBREVIATION' => 'PRY'], ['COUNTRY' => 'PERU', 'ABBREVIATION' => 'PER'], ['COUNTRY' => 'PHILIPPINES', 'ABBREVIATION' => 'PHL'], ['COUNTRY' => 'PITCAIRN', 'ABBREVIATION' => 'PCN'], ['COUNTRY' => 'POLAND', 'ABBREVIATION' => 'POL'], ['COUNTRY' => 'PORTUGAL', 'ABBREVIATION' => 'PRT'], ['COUNTRY' => 'PUERTORICO', 'ABBREVIATION' => 'PRI'], ['COUNTRY' => 'QATAR', 'ABBREVIATION' => 'QAT'], ['COUNTRY' => 'REUNION', 'ABBREVIATION' => 'REU'], ['COUNTRY' => 'ROMANIA', 'ABBREVIATION' => 'ROU'], ['COUNTRY' => 'RUSSIANFEDERATION', 'ABBREVIATION' => 'RUS'], ['COUNTRY' => 'RWANDA', 'ABBREVIATION' => 'RWA'], ['COUNTRY' => 'SAINTHELENA', 'ABBREVIATION' => 'SHN'], ['COUNTRY' => 'SAINTKITTSANDNEVIS', 'ABBREVIATION' => 'KNA'], ['COUNTRY' => 'SAINTLUCIA', 'ABBREVIATION' => 'LCA'], ['COUNTRY' => 'SAINTPIERREANDMIQUELON', 'ABBREVIATION' => 'SPM'], ['COUNTRY' => 'SAINTVINCENT&GRENADINES', 'ABBREVIATION' => 'VCT'], ['COUNTRY' => 'SAMOA', 'ABBREVIATION' => 'WSM'], ['COUNTRY' => 'SANMARINO', 'ABBREVIATION' => 'SMR'], ['COUNTRY' => 'SAOTOMEANDPRINCIPE', 'ABBREVIATION' => 'STP'], ['COUNTRY' => 'SAUDIARABIA', 'ABBREVIATION' => 'SAU'], ['COUNTRY' => 'SENEGAL', 'ABBREVIATION' => 'SEN'], ['COUNTRY' => 'SERBIA', 'ABBREVIATION' => 'SRB'], ['COUNTRY' => 'SEYCHELLES', 'ABBREVIATION' => 'SYC'], ['COUNTRY' => 'SIERRALEONE', 'ABBREVIATION' => 'SLE'], ['COUNTRY' => 'SINGAPORE', 'ABBREVIATION' => 'SGP'], ['COUNTRY' => 'SLOVAKIA(SLOVAKREPUBLIC)', 'ABBREVIATION' => 'SVK'], ['COUNTRY' => 'SLOVENIA', 'ABBREVIATION' => 'SVN'], ['COUNTRY' => 'SOLOMONISLANDS', 'ABBREVIATION' => 'SLB'], ['COUNTRY' => 'SOMALIA', 'ABBREVIATION' => 'SOM'], ['COUNTRY' => 'SOUTHAFRICA', 'ABBREVIATION' => 'ZAF'], ['COUNTRY' => 'SOUTHGEORGIA&SOUTHSANDWICHISLANDS', 'ABBREVIATION' => 'SGS'], ['COUNTRY' => 'SPAIN', 'ABBREVIATION' => 'ESP'], ['COUNTRY' => 'SRILANKA', 'ABBREVIATION' => 'LKA'], ['COUNTRY' => 'SUDAN', 'ABBREVIATION' => 'SDN'], ['COUNTRY' => 'SURINAME', 'ABBREVIATION' => 'SUR'], ['COUNTRY' => 'SVALBARD&JANMAYENISLANDS', 'ABBREVIATION' => 'SJM'], ['COUNTRY' => 'SWAZILAND', 'ABBREVIATION' => 'SWZ'], ['COUNTRY' => 'SWEDEN', 'ABBREVIATION' => 'SWE'], ['COUNTRY' => 'SWITZERLAND', 'ABBREVIATION' => 'CHE'], ['COUNTRY' => 'SYRIA', 'ABBREVIATION' => 'SYR'], ['COUNTRY' => 'TAIWAN', 'ABBREVIATION' => 'TWN'], ['COUNTRY' => 'TAJIKISTAN', 'ABBREVIATION' => 'TJK'], ['COUNTRY' => 'THAILAND', 'ABBREVIATION' => 'THA'], ['COUNTRY' => 'TOGO', 'ABBREVIATION' => 'TGO'], ['COUNTRY' => 'TOKELAU', 'ABBREVIATION' => 'TKL'], ['COUNTRY' => 'TONGA', 'ABBREVIATION' => 'TON'], ['COUNTRY' => 'TRINIDADANDTOBAGO', 'ABBREVIATION' => 'TTO'], ['COUNTRY' => 'TUNISIA', 'ABBREVIATION' => 'TUN'], ['COUNTRY' => 'TURKEY', 'ABBREVIATION' => 'TUR'], ['COUNTRY' => 'TURKMENISTAN', 'ABBREVIATION' => 'TKM'], ['COUNTRY' => 'TURKSANDCAICOSISLANDS', 'ABBREVIATION' => 'TCA'], ['COUNTRY' => 'TUVALU', 'ABBREVIATION' => 'TUV'], ['COUNTRY' => 'UGANDA', 'ABBREVIATION' => 'UGA'], ['COUNTRY' => 'UKRAINE', 'ABBREVIATION' => 'UKR'], ['COUNTRY' => 'UNITEDARABEMIRATES', 'ABBREVIATION' => 'ARE'], ['COUNTRY' => 'UKCITIZEN', 'ABBREVIATION' => 'GBR'], ['COUNTRY' => 'UNITEDSTATESOFAMERICA', 'ABBREVIATION' => 'USA'], ['COUNTRY' => 'URUGUAY', 'ABBREVIATION' => 'URY'], ['COUNTRY' => 'UZBEKISTAN', 'ABBREVIATION' => 'UZB'], ['COUNTRY' => 'VANUATU', 'ABBREVIATION' => 'VUT'], ['COUNTRY' => 'VENEZUELA', 'ABBREVIATION' => 'VEN'], ['COUNTRY' => 'VIETNAM', 'ABBREVIATION' => 'VNM'], ['COUNTRY' => 'VIRGINISLANDS(BRITISH)', 'ABBREVIATION' => 'VGB'], ['COUNTRY' => 'VIRGINISLANDS(U.S.)', 'ABBREVIATION' => 'VIR'], ['COUNTRY' => 'WALLISANDFUTUNAISLANDS', 'ABBREVIATION' => 'WLF'], ['COUNTRY' => 'WESTERNSAHARA', 'ABBREVIATION' => 'ESH'], ['COUNTRY' => 'YEMEN', 'ABBREVIATION' => 'YEM'], ['COUNTRY' => 'YUGOSLAVIA', 'ABBREVIATION' => 'YUG'], ['COUNTRY' => 'ZAMBIA', 'ABBREVIATION' => 'ZMB'], ['COUNTRY' => 'ZIMBABWE', 'ABBREVIATION' => 'ZWE'], ['COUNTRY' => 'ALANDISLANDS', 'ABBREVIATION' => 'ALA'], ['COUNTRY' => 'BONAIRE,SINTEUSTATIUSANDSABA', 'ABBREVIATION' => 'BES',], ['COUNTRY' => 'SAINTBARTHELEMY', 'ABBREVIATION' => 'BLM'], ['COUNTRY' => 'CURACAO', 'ABBREVIATION' => 'CUW'], ['COUNTRY' => 'SAINTMARTIN', 'ABBREVIATION' => 'MAF'], ['COUNTRY' => 'SOUTHSUDAN', 'ABBREVIATION' => 'SSD'], ['COUNTRY' => 'SINTMAARTEN(DUTCHPART)', 'ABBREVIATION' => 'SXM'], ['COUNTRY' => 'UNITEDSTATESMINOROUTLYINGISLANDS', 'ABBREVIATION' => 'UMI'], ['COUNTRY' => 'UK-DEPENDENTTERRITORIESCITIZEN', 'ABBREVIATION' => 'GBD'], ['COUNTRY' => 'UK-NATIONAL(OVERSEAS)', 'ABBREVIATION' => 'GBN'], ['COUNTRY' => 'UK-OVERSEASCITIZEN', 'ABBREVIATION' => 'GBO'], ['COUNTRY' => 'UNITEDNATIONSORGANIZATION', 'ABBREVIATION' => 'UNO'], ['COUNTRY' => 'UNSPECIALIZEDAGENCYOFFICIAL', 'ABBREVIATION' => 'UNA'], ['COUNTRY' => 'STATELESS', 'ABBREVIATION' => 'XXA'], ['COUNTRY' => 'REFUGEE', 'ABBREVIATION' => 'XXB'], ['COUNTRY' => 'REFUGEE(NON-CONVENTION)', 'ABBREVIATION' => 'XXC'], ['COUNTRY' => 'UNSPECIFIED/UNKNOWN', 'ABBREVIATION' => 'XXX'], ['COUNTRY' => 'UK-PROTECTEDPERSON', 'ABBREVIATION' => 'GBP'], ['COUNTRY' => 'UK-SUBJECT', 'ABBREVIATION' => 'GBS'], ['COUNTRY' => 'AFRICANDEVELOPMENTBANK', 'ABBREVIATION' => 'XBA'], ['COUNTRY' => 'AFRICANEXPORT–IMPORTBANK', 'ABBREVIATION' => 'XIM'], ['COUNTRY' => 'CARIBBEANCOMMUNITYORONEOFITSEMISSARIES', 'ABBREVIATION' => 'XCC'], ['COUNTRY' => 'COMMONMARKETFOREASTERNANDSOUTHERNAFRICA', 'ABBREVIATION' => 'XCO'], ['COUNTRY' => 'ECONOMICCOMMUNITYOFWESTAFRICANSTATES', 'ABBREVIATION' => 'XEC'], ['COUNTRY' => 'INTERNATIONALCRIMINALPOLICEORGANIZATION', 'ABBREVIATION' => 'XPO'], ['COUNTRY' => 'SOVEREIGNMILITARYORDEROFMALTA', 'ABBREVIATION' => 'XOM']
        ];
    }
}
