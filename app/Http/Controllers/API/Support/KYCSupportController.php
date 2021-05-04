<?php

namespace App\Http\Controllers\API\Support;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\KYCSupportRequest;
use Illuminate\Support\Facades\Log;
use Session;
use Route;


class KYCSupportController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN,ROLE_BACK_OFFICE,ROLE_FORENSIC,ROLE_CHECKER']);
        $this->middleware(['role:ROLE_CHECKER,ROLE_ADMIN'])->only(['getSingleAltVisitorRegs', 'getAllAltVisitorRegs', 'reviewVisitorAlternativeReg']);
    }

    public function registrationPerID(KYCSupportRequest $request)
    {
        $body = [
            'IDNumber' => $request->idNumber,
            'RequestType' => (int) $request->reportType
        ];

        $url = 'MsisdnListPerIDNumber';

        $data = $this->postRequest($url, $body);

        if ($data['ErrorCode'] == 0) {
            return response()->json($data, 200);
        }

        // if(isset($data) && $data['DetailedListOfMsisdn'] !== null)
        // {

        // }
        elseif ($data['ErrorCode'] == 20) {
            return response()->json([
                'message' => 'Customer registration details not found !'
            ], 400);
        } else {
            return response()->json([
                'message' => 'An error has occured !'
            ], 400);
        }
    }

    public function getSingleAltVisitorRegs(Request $request)
    {
        $body = [
            'RegID' => (int) $request->RegID,
            'UserID' => $this->user['UserID'],
        ];

        $url = 'GetSinglePendingRegistration';

        $data = $this->postRequest($url, $body);

        return response()->json($data, 200);
    }

    public function getAllAltVisitorRegs()
    {
        $url = 'GetAllPendingRegs/' . $this->user['UserID'];

        $registrations = $this->getRequest($url);

        return response()->json($registrations, 200);
    }

    public function reviewVisitorAlternativeReg(KYCSupportRequest $request)
    {
        $body = [
            'RegID' => (int) $request->regID,
            'IDNumber' => $request->idNumber,
            'MSISDN' => $request->msisdn,
            'FirstName' => $request->firstName,

            'MiddleName' =>  $request->middleName,
            'Gender' =>  $request->gender,
            'Dob' => $request->dob,
            'Surname' => $request->lastName,

            'ResidentRegion' =>  $request->region,
            'ResidentDistrict' =>  $request->district,
            'ResidentWard' => $request->ward,
            'ResidentStreet' => $request->street,

            'Nationality' =>  $request->nationality,
            'VerificationStatus' => (int) $request->verificationStatus,
            'DeclinedReason' => $request->declineReason ? $request->declineReason : null,
            'UserID' => $this->user['UserID'],
        ];

        $url = 'VerifyRegistration';

        $data = $this->postRequest($url, $body);

        Log::channel('Visitor-alt-register-review')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            return response()->json(null, 200);
        } else {
            return response()->json([
                'message' => 'An error has occured !'
            ], 400);
        }
    }
}
