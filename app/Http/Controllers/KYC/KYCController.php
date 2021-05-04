<?php

namespace App\Http\Controllers\KYC;

use Illuminate\Http\Request;
use Session;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\KycRequest;
use Illuminate\Support\Facades\Log;
use Route;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Client;
use function GuzzleHttp\json_encode;
use Illuminate\Support\Arr;

class KYCController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_REGISTRAL,ROLE_SPECIAL_REGISTRAL,ROLE_MAKER'])->except(['getRegionId', 'getDistrict', 'getWard', 'getVillage', 'viewCustomerRegDetails', 'getCustomerRegDetails', 'ShowRegisterDiplomat', 'registerDiplomatSave', 'showBulkDiplomatForm1', 'showBulkDiplomatForm2', 'bulkDiplomatProcessPage1', 'bulkDiplomatProcessPage2']);
        $this->middleware(['role:ROLE_SPECIAL_REGISTRAL'])->only(['ShowRegisterDiplomat', 'registerDiplomatSave', 'showBulkDiplomatForm1', 'showBulkDiplomatForm2', 'bulkDiplomatProcessPage1', 'bulkDiplomatProcessPage2']);
    }

    public function show_newReg()
    {
        return view('register.nida.new.new');
    }

    public function checkMSISDN_newReg(KycRequest $request)
    {
        if ($this->checkBlockedNumbers($request->get('phoneNumber'))) {
            return response()->json(['message' => 'This customer is NOT allowed to get registered . Thank you!'], 400);
        }

        $data = $this->checkMSISDNIcap($request);

        //Customer is Bio-Registered
        if ($data['bioRegStatus'] === 'Y' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is already Biometrically registered. Thank you!'], 400);
        } //Customer is E-Registered not Bio-Registered
        elseif ($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is already registered, but NOT Bio-registered. Thank you!'], 400);
        } //Customer is New
        elseif (($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'NONE') || ($data['bioRegStatus'] === 'Y' && $data['RegistrationStatus'] === 'NONE')) {
            $request->session()->put('msisdn', $request->get('phoneNumber'));
            return response()->json(['message' => 'This customer is Not registered. Please continue !'], 200);
        }

        return response()->json(['message' => 'Something went wrong. Please try again !'], 400);
    }

    // public function register_new_MSISDN_Icap(KycRequest $request)
    // {
    //     $msisdn = $request->session()->get('msisdn');

    //     $body = [
    //         'NIN' => $request->get('NIN'),
    //         'FingerCode' => $request->get('fingerCode'),
    //         'FingerData' => $request->get('fingerData'),
    //         'MSISDN' => $msisdn,
    //         'UserID' => $this->user['UserID'],
    //         'Longtude' => '00000',
    //         'Latitude' => '00000',
    //         'Platform' => 'web',
    //         'RegType' => 'New'
    //     ];

    //     $url = 'QueryNIDABio';

    //     $data = $this->postRequest($url, $body);

    //     unset( $body['FingerData']);
    //     unset( $data['PHOTO']);
    //     unset( $data['SIGNATURE']);

    //     Log::channel('New-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

    //     if ($data['ErrorCode'] == 0) {
    //         $request->session()->forget('msisdn');
    //         return response()->json(['message' => 'Successful Customer Registration. Thank you!'], 200);
    //     } elseif ($data['ErrorCode'] == 132) {
    //         return response()->json(['message' => 'Customer NIN is not Found. Try again !'], 400);
    //     } elseif ($data['ErrorCode'] == 141) {
    //         return response()->json(['message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !'], 400);
    //     } elseif ($data['ErrorCode'] == 01) {
    //         return response()->json(['message' => 'Customer Biometric Fingerprint Verification Failed 01. Try again !'], 400);
    //     } elseif ($data['ErrorCode'] == 44) {
    //         return response()->json(['message' => 'Customer Registration failed . Try again after 30 minutes !'], 400);
    //     }  elseif ($data['ErrorCode'] == 45) {
    //         return response()->json(['message' => 'Customer MSISDN already registered !'], 400);
    //     }  elseif ($data['ErrorCode'] == 46) {
    //     return response()->json(['message' => 'Customer NIN has already five(5) or more MSISDN ! '], 400);
    //     } elseif ($data['ErrorCode'] == '172') {
    //         $request->session()->put('nin', $request->get('NIN'));
    //         return response()->json(['NIDACode' => 172], 200);
    //     }else {
    //         return response()->json(['message' => 'Sorry ! Something Went Wrong. Please try again !'], 400);
    //     }

    //     //$request->session()->forget('msisdn');

    //     return response()->json(['message' => 'Ooops ! Something Went Wrong. Please try again !'], 400);
    // }

    public function show_reReg()
    {
        return view('register.nida.re-reg.re-reg');
    }

    public function re_register_MSISDN(KycRequest $request)
    {
        $msisdn = $request->session()->get('msisdn');

        $body = [
            'NIN' => $request->get('NIN'),
            'FingerCode' => $request->get('fingerCode'),
            'FingerData' => $request->get('fingerData'),
            'MSISDN' => $msisdn,
            'UserID' => $this->user['UserID'],
            'Longtude' => '00000',
            'Latitude' => '00000',
            'Platform' => 'web',
            'RegType' => 're-Reg'
        ];

        $url = 'ReReg';

        $data = $this->postRequest($url, $body);

        unset($body['FingerData']);

        Log::channel('Re-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['StatusCode'] == '132') {
            return response()->json(['message' => 'Customer NIN is not Found. Try again !'], 400);
        } elseif ($data['StatusCode'] == '172') {
            $request->session()->put('nin', $request->get('NIN'));
            return response()->json(['NIDACode' => 172], 200);
        } elseif ($data['StatusCode'] == 45) {
            return response()->json(['message' => 'Customer NIN has already five(5) or more MSISDN registered !'], 400);
        } elseif ($data['StatusCode'] == 55) {
            return response()->json(['message' => 'Customer MSISDN already registered !'], 400);
        } elseif ($data['StatusCode'] == '141') {
            return response()->json(['message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !'], 400);
        } elseif ($data['StatusCode'] == '01') {
            return response()->json(['message' => 'Customer Biometric Fingerprint Verification Failed 01. Try again !'], 400);
            // } elseif ($data['IcapRegStatus'] == 'Failed') {
            //     return response()
            //         ->json([
            //             'message' => 'Sorry, NameCheck did not pass, having a matching score of ' . round($data['NameMatchScore']) . ' %',
            //         ], 400);
        } elseif ($data['IcapRegStatus'] == 'Success') {
            $request->session()->forget('msisdn');
            $request->session()->put('nin', $request->get('NIN'));
            return response()->json(['message' => 'Successful Customer re-Registration. Thank you!'], 200);
        } elseif ($data['OTPSent'] == 'Y') {
            return response()->json(['OTP' => true], 200);
        }

        return response()->json(['message' => 'Ooops ! Something Went Wrong. Please try again !'], 400);
    }

    public function registerTotalMismatch(Request $request)
    {
        $body = [
            'Msisdn' => $request->session()->get('msisdn'),
            'UserID' => $this->user['UserID'],
            'Otp' => $request->OTP,
            'Platform' => 'web'
        ];

        $url = 'TotalMissmatch';

        $data = $this->postRequest($url, $body);

        Log::channel('Total-mismatch')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['RegStatus'] == 'Success') {
            $request->session()->forget('msisdn', 'nin');
            return response()
                ->json([
                    'code' => 200,
                    'message' => 'Successful Customer Re-registration !',
                ], 200);
        } elseif ($data['SongeshaLoan'] == true) {
            $request->session()->forget('msisdn', 'nin');
            return response()
                ->json([
                    'code' => 400,
                    'message' => 'Customer has Songesha loan. Please advice to pay the loan !',
                ], 200);
        } elseif ($data['RegStatus'] == 'Incorecct otp') {
            return response()
                ->json([
                    'code' => 400,
                    'message' => 'Invalid OTP !',
                ], 400);
        }

        return response()
            ->json([
                'message' => 'Oops , An Internal Error occured !',
            ], 400);
    }

    public function recheckMSISDNIcap(KycRequest $request)
    {
        $data = $this->checkMSISDNIcap($request);

        $request->session()->put('msisdn', $request->get('phoneNumber'));

        //return response()->json($data, 200);

        //Customer is Bio-Registered
        if ($data['bioRegStatus'] === 'Y' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is already Biometrically registered. Thank you!'], 400);
        } //Customer is E-Registered not Bio-Registered
        elseif (($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'REGISTERED')) {
            $request->session()->put('msisdn', $request->get('phoneNumber'));
            return response()->json(['message' => 'This customer is Not Bio-registered. Please continue !'], 200);
        } elseif ($data['bioRegStatus'] == ' ' && $data['RegistrationStatus'] === 'REGISTERED') {
            $request->session()->put('msisdn', $request->get('phoneNumber'));
            return response()->json(['message' => 'This customer is Not Bio-registered. Please continue !'], 200);
        }
        //Customer is New
        elseif ($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'NONE') {
            return response()->json(['message' => 'This customer is NOT registered. Thank you!'], 400);
        }

        return response()->json(['message' => 'Something went wrong. Please try again !'], 400);
    }

    public function searchRegistration()
    {
        return view('register.search-msisdn');
    }

    public function getCustomerDetails(KycRequest $request)
    {
        $body = [
            'Msisdn' => $request->get('phoneNumber')
        ];

        $url = 'SingleCustomer';

        $data = $this->postRequest($url, $body);

        if ($data) {
            return response()->json(['customer' => $data], 200);
        }

        return response()->json(['message' => 'Something went wrong', 400]);
    }

    public function getNewRegDefacedQuestion()
    {
        $body = [
            'NIN' => Session::get('nin'),
            'QuestionCode' => '',
            'QuestionAnswer' => '',
            'MSISDN' => Session::get('msisdn'),
            'UserID' => $this->user['UserID'],
            'Longtude' => '00000',
            'Latitude' => '00000',
            'RegType' => 'New',
            'Platform' => 'web',
        ];

        $url = 'DefacedNewReg';

        $data = $this->postRequest($url, $body);

        Log::channel('New-defaced')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        return response()->json($data, 200);
    }

    public function getNewRegDefacedAnswer(Request $request)
    {
        $body = [
            'NIN' => Session::get('nin'),
            'QuestionCode' => $request->get('QuestionCode'),
            'QuestionAnswer' => $request->get('defaced_answer'),
            'MSISDN' => Session::get('msisdn'),
            'UserID' => $this->user['UserID'],
            'Longtude' => '00000',
            'Latitude' => '00000',
            'RegType' => 'New',
            'Platform' => 'web',
        ];

        $url = 'DefacedNewReg';

        $data = $this->postRequest($url, $body);

        Log::channel('New-defaced')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        return response()->json($data, 200);
    }

    public function getDefacedQuestion()
    {
        $body = [
            'NIN' => Session::get('nin'),
            'QuestionCode' => '',
            'QuestionAnswer' => '',
            'MSISDN' => Session::get('msisdn'),
            'UserID' => $this->user['UserID'],
            'Longtude' => '00000',
            'Latitude' => '00000',
            'RegType' => 're-Reg',
            'Platform' => 'web',
        ];

        $url = 'NIDAQuestion';

        $data = $this->postRequest($url, $body);

        Log::channel('Re-Reg-defaced')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        return response()->json($data, 200);
    }

    public function getDefacedAnswer(Request $request)
    {
        $body = [
            'NIN' => Session::get('nin'),
            'QuestionCode' => $request->get('QuestionCode'),
            'QuestionAnswer' => $request->get('defaced_answer'),
            'MSISDN' => Session::get('msisdn'),
            'UserID' => $this->user['UserID'],
            'Longtude' => '00000',
            'Latitude' => '00000',
            'RegType' => 're-Reg',
            'Platform' => 'web',
        ];

        $url = 'NIDAQuestion';

        $data = $this->postRequest($url, $body);

        Log::channel('Re-Reg-defaced')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        return response()->json($data, 200);
    }

    public function checkMSISDNIcap($request)
    {
        $body = [
            'MSISDN' => $request->get('phoneNumber'),
            'UserID' => $this->user['UserID']
        ];

        $url = 'QRYKYC';

        $data = $this->postRequest($url, $body);

        return $data;
    }

    public function showSIMSwapPage()
    {
        return view('register.nida.sim-swap.sim-swap');
    }

    public function checkMSISDN_SIMSwap(KycRequest $request)
    {
        $data = $this->checkMSISDNIcap($request);

        //Customer is Bio-Registered
        if ($data['bioRegStatus'] === 'Y' && $data['RegistrationStatus'] === 'REGISTERED') {
            $request->session()->put('msisdn', $request->get('phoneNumber'));
            return response()->json(['message' => 'This customer is Biometrically registered. Please continue'], 200);
        } //Customer is E-Registered not Bio-Registered
        elseif ($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'REGISTERED') {
            return response()->json(['message' => 'This customer is Not Bio-registered. Thank you! !'], 400);
        } //Customer is New
        elseif ($data['bioRegStatus'] === 'N' && $data['RegistrationStatus'] === 'NONE') {
            return response()->json(['message' => 'This customer is NOT registered. Thank you!'], 400);
        } elseif ($data['Code'] == 2) {
            return response()->json(['message' => 'Sorry, An Error has Occcured on iCAP !'], 400);
        }

        return response()->json(['message' => 'Something went wrong. Please try again !'], 400);
    }

    public function saveSIMSwapReg(Request $request)
    {
        $messages = [
            'ICCID.required' => 'We need to know SIM\'s ICCID number!',
            'ICCID.digits' => 'Invalid SIM\'s ICCID number!',
            'NIN.required' => 'We need to know Customer\'s NIDA ID !',
            'NIN.digits' => 'Invalid Customer\'s NIDA ID Format !',
            'fingerCode.required' => 'We need to know Customer\'s finger index !',
            'fingerData.required' => 'We need to know Customer\'s finger print !'

        ];

        $this->validate($request, [
            'ICCID' => 'required|digits:19',
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ], $messages);

        $body = [
            'ICCID' => $request->ICCID,
            'NIN' => $request->NIN,
            'FingerCode' => $request->fingerCode,
            'FingerData' => $request->fingerData,
            'UserID' => $this->user['UserID'],
            'MSISDN' => $request->session()->get('msisdn')
        ];

        $url = 'SimSwap';

        $data = $this->postRequest($url, $body);

        unset($body['FingerData']);

        Log::channel('SIM-swap')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 0 && $data['Description'] == null) {
            return response()
                ->json([
                    'message' => 'Successful Customer MSISDN SIM Swap !',
                    'status' => $data['ID']
                ], 200);
        } elseif ($data['ID'] == 85) {
            return response()
                ->json([
                    'message' => 'Sim hii ilishafanyiwa swap,jaribio limeshindikana',
                    'status' => $data['ID']
                ], 400);
        }
        return response()
            ->json([
                'message' => 'Sorry, Something went wrong . Try again !',
            ], 400);
    }

    public function showForeignerSIMRegPage()
    {
        //dd( $this->ImmigrationCountryList());
        return view('register.foreigner.new.foreigner-sim-reg')->with('country', $this->ImmigrationCountryList());
    }

    public function foreigner_register_new_MSISDN(Request $request)
    {
        $msisdn = $request->session()->get('msisdn');

        $messages = [
            'issuingCountry.required' => 'We need to know Issuing Country Code !',
            //'immigrationCode.required' => 'We need to know Immigration Document Number !',
            'PassportID.required' => 'We need to know Customer\'s Passport Number !',
            'fingerCode.required' => 'We need to know Customer\'s finger index !',
            'fingerData.required' => 'We need to know Customer\'s finger print !',
        ];

        $this->validate($request, [
            'issuingCountry' => 'required',
            'PassportID' => 'required',
            'fingerCode' => 'required',
            'fingerData' => 'required',
            //'immigrationCode' => 'required'
        ], $messages);

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

        $immigrationReq = [
            'DocumentNo' => $request->get('PassportID'),
            'IssuingCountry' => trim($request->get('issuingCountry')),
            //'ImmigrationDocNo' => $request->immigrationCode,
            'RThumb' => $fingerDataR1,
            //'RThumb'=> $rightThumb,
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
            'Msisdn' => $msisdn,
            'UserID' => $this->user['UserID'],
            'Platform' => 'web',
            'RegType' => 'New'
        ];

        $url = 'Uhamiaji';

        $data = $this->postRequest($url, $body);

        foreach ($immigrationReq as $key => $value) {
            if (in_array($value, $fingerArray) && ($value !== null)) {
                unset($key);
            }
        }

        Log::channel('New-foreigner')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ApiRequestStatus'] == 'Fail from Immigration') {
            return response()->json(['message' => 'Customer Biometric Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['RegistrationStatus'] == 'Fail Icap' || $data['IcapRegStatus'] == 'Could not be Updated') {
            return response()->json(['message' => 'Customer Registration Failed from Icap. Try again !'], 400);
        } elseif ($data['VerificationStatus'] == null && $data['RegistrationStatus'] == null && $data['IcapRegStatus'] == null) {
            return response()->json(['message' => 'Failed to load Results from Immigration. Try again !'], 400);
        } elseif ($data['RegistrationStatus'] == 'subject does not match with provided fingerprints.') {
            return response()->json(['message' => 'Customer Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['IcapRegStatus'] == 'Fail Icap') {
            return response()->json(['message' => 'Customer Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['VerificationStatus'] == '44') {
            return response()->json(['message' => 'Customer Verification Failed. Try again after 30 minutes !'], 400);
        } elseif ($data['VerificationStatus'] == 'an internal error occured.') {
            return response()->json(['message' => 'Error from Immigration. Try again !'], 400);
        } elseif ($data['IcapRegStatus'] == 'Success' && ($data['VerificationStatus'] == 'subject verified' || $data['VerificationStatus'] == 'subject verified.') && $data['RegistrationStatus'] == 'Registered') {
            return response()
                ->json([
                    'message' => 'Successful Customer Registration. Thank you!',
                ], 200);
        }

        return response()->json(['message' => 'Ooops ! Something Went Wrong. Please try again !'], 400);
    }

    public function showCheckSIMRegPage()
    {
        return view('register.check-sim-reg');
    }

    public function getSIMRegStatus(Request $request)
    {
        $data = $this->checkMSISDNIcap($request);

        return response()->json($data, 200);
    }

    private function checkBlockedNumbers($msisdn)
    {
        $hayStack = ['0754376797', '0748333444'];
        if (in_array($msisdn, $hayStack)) {
            return TRUE;
        }
        return FALSE;
    }

    public function showForeignerReRegPage()
    {
        return view('register.foreigner.re-reg.foreigner-re-reg')->with('country', $this->ImmigrationCountryList());
    }

    public function foreigner_re_register_MSISDN(Request $request)
    {
        $msisdn = $request->session()->get('msisdn');

        $messages = [
            'issuingCountry.required' => 'We need to know Issuing Country Code !',
            'PassportID.required' => 'We need to know Customer\'s Passport Number !',
            'fingerCode.required' => 'We need to know Customer\'s finger index !',
            'fingerData.required' => 'We need to know Customer\'s finger print !',
            //'immigrationCode.required' => 'We need to know Immigration Document Number !',
        ];

        $this->validate($request, [
            'issuingCountry' => 'required',
            'PassportID' => 'required',
            'fingerCode' => 'required',
            'fingerData' => 'required',
            //'immigrationCode' => 'required'
        ], $messages);

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

        $immigrationReq = [
            'DocumentNo' => $request->get('PassportID'),
            'IssuingCountry' => $request->get('issuingCountry'),
            //'ImmigrationDocNo' => $request->immigrationCode,
            'RThumb' => $fingerDataR1,
            //'RThumb'=> $rightThumb,
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
            'Msisdn' => $msisdn,
            'UserID' => $this->user['UserID'],
            'Platform' => 'web',
            'RegType' => 're-reg'
        ];

        $url = 'ReregForeigners';

        $data = $this->postRequest($url, $body);

        foreach ($immigrationReq as $key => $value) {
            if (in_array($value, $fingerArray) && ($value !== null)) {
                unset($key);
            }
        }

        Log::channel('Re-Reg-foreigner')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ApiRequestStatus'] == 'Fail from Immigration') {
            return response()->json(['message' => 'Customer Biometric Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['RegistrationStatus'] == 'Fail Icap' || $data['IcapRegStatus'] == 'Could not be Updated') {
            return response()->json(['message' => 'Customer Registration Failed from Icap. Try again !'], 400);
        } elseif ($data['RegistrationStatus'] == 'subject does not match with provided fingerprints.') {
            return response()->json(['message' => 'Customer Biometric Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['RegistrationStatus'] == 'subject does not match with provided fingerprints.') {
            return response()->json(['message' => 'Customer Biometric Verification Failed from Immigration. Try again !'], 400);
        } elseif ($data['VerificationStatus'] == null && $data['RegistrationStatus'] == null && $data['IcapRegStatus'] == null) {
            return response()->json(['message' => 'Failed to load Results from Immigration. Try again !'], 400);
        } elseif ($data['VerificationStatus'] == 'an internal error occured.') {
            return response()->json(['message' => 'Error from Immigration. Try again !'], 400);
        } elseif ($data['VerificationStatus'] == '44') {
            return response()->json(['message' => 'Customer Verification Failed. Try again after 10 minutes !'], 400);
        } elseif ($data['VerificationStatus'] == 'subject does not match with provided fingerprints.') {
            return response()->json(['message' => 'Customer Biometric Verification Failed from Immigration. Try again !'], 400);
            // }elseif ($data['IcapRegStatus'] == 'Failed') {
            //     $request->session()->forget('msisdn');
            //     return response()->json(['message' => 'Customer Registration Failed, having a matching score of ' . round($data['NameMatchScore']) . ' %','Code' => 01
            // ], 200);
        } elseif ($data['OTPSentYN'] == 'Y') {
            return response()->json(['OTP' => true], 200);
        } elseif ($data['IcapRegStatus'] == 'Success') {
            $request->session()->forget('msisdn');
            return response()
                ->json([
                    'message' => 'Successful Customer re-Registration. Thank you!', 'Code' => 00
                ], 200);
        }

        return response()->json(['message' => 'Ooops ! Something Went Wrong. Please try again !'], 400);
    }

    public function ShowRegisterDiplomat()
    {
        return view('register.diplomat.single.diplomat-register')->with('country', $this->getCountryList());
    }

    public function registerDiplomatSave(KycRequest $request)
    {

        $IDFrontFile = file_get_contents($request->file('front-id-file'));
        $IDFrontFilebase64 = base64_encode($IDFrontFile);

        $IDBackFile = file_get_contents($request->file('back-id-file'));
        $IDBackFilebase64 = base64_encode($IDBackFile);

        $PassportFile = file_get_contents($request->file('passport-file'));
        $PassportFilebase64 = base64_encode($PassportFile);

        $body = [
            'MSISDN' => $request->msisdn,
            'FirstName' => $request->firstName,
            'MiddleName' => $request->middleName,
            'Surname' => $request->lastName,

            'PassportNumber' => $request->get('passport-number'),
            'IDNumber' => $request->get('id-number'),
            'Gender' => $request->gender,
            'Institution' => $request->institution,
            'Dob' => $request->dob,

            'Country' => $request->country,
            'FrontIDImage' => $IDFrontFilebase64,
            'BackIDImage' => $IDBackFilebase64,
            'PassportImage' => $PassportFilebase64,

            'UserID' => $this->user['UserID']
        ];

        $url = 'RegisterDiplomat';

        $data = $this->postRequest($url, $body);

        unset($body['FrontIDImage']);
        unset($body['BackIDImage']);
        unset($body['PassportImage']);

        Log::channel('Single-Diplomat-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 0) {
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

    public function ShowAllDiplomats()
    {
        $url = 'GetDiplomats?id=' . $this->user['UserID'];
        $data = $this->getRequest($url);

        return view('register.diplomat.diplomat-list')->with('diplomat', $data);
    }

    public function showBulkDiplomatForm1()
    {
        session()->forget('data');
        return view('register.diplomat.bulk.diplomat-bulk-form1')->with('regions', $this->getRegions());
    }

    public function showBulkDiplomatForm2()
    {
        return view('register.diplomat.bulk.diplomat-bulk-form2')->with('country', $this->getCountryList());
    }

    public function bulkDiplomatProcessPage1(KycRequest $request)
    {

        $msisdnFile = file_get_contents($request->file('msisdn-file'));
        $ImsisdnFilebase64 = base64_encode($msisdnFile);

        $body = [
            'VillageID' => $request->village,
            'Institution' => $request->institution,
            'Address' => $request->adress,

            'MSISDNFile' => $ImsisdnFilebase64,
            'PostalCode' => $request->get('post-code')
        ];

        $request->session()->put('data', $body);

        return redirect('diplomat-registration-bulk2')->with('country', $this->getCountryList());

        //return json_encode($body,200);
    }

    public function bulkDiplomatProcessPage2(KycRequest $request)
    {

        $AgentIDFile = file_get_contents($request->file('agentID-file'));
        $AgentIDFilebase64 = base64_encode($AgentIDFile);

        $IDFrontFile = file_get_contents($request->file('front-id-file'));
        $IDFrontFilebase64 = base64_encode($IDFrontFile);

        $IDBackFile = file_get_contents($request->file('back-id-file'));
        $IDBackFilebase64 = base64_encode($IDBackFile);

        $PassportFile = file_get_contents($request->file('passport-file'));
        $PassportFilebase64 = base64_encode($PassportFile);

        $body1 = $request->session()->get('data');

        $body = [
            'MSISDN' => $request->msisdn,
            'FirstName' => $request->firstName,
            'MiddleName' => $request->middleName,
            'Surname' => $request->lastName,

            'PassportNumber' => $request->get('passport-number'),
            'ExpireDate' => $request->get('expiry-date'),
            'IDNumber' => $request->get('id-number'),
            'Gender' => $request->gender,
            'Dob' => $request->dob,

            'Country' => $request->country,
            'FrontIDImage' => $IDFrontFilebase64,
            'BackIDImage' => $IDBackFilebase64,
            'PassportImage' => $PassportFilebase64,
            'AgentIDImage' => $AgentIDFilebase64,

            'Institution' => $body1['Institution'],
            'Address' => $body1['Address'],
            'PostalCode' => $body1['PostalCode'],
            'MSISDNFile' => $body1['MSISDNFile'],
            'VillageID' => $body1['VillageID'],
            'Email' => $request->email,

            'UserID' => $this->user['UserID']
        ];

        $url = 'RegisterDiplomatBulk';

        $data = $this->postRequest($url, $body);

        // return response()->json($data, 200);
        //return json_encode($data);

        Log::channel('Bulk-Diplomat-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 0) {
            $request->session()->forget('data');
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 200);
        }
        return response()
            ->json([
                'message' => 'Sorry, Something went wrong . Try again !',
            ], 400);
    }

    public function ShowRegisterMinor()
    {
        return view('register.minor-register')->with('country', $this->getCountryList());
    }

    public function registerMinorSave_page2(KycRequest $request)
    {
        $body = [
            'guardian-msisdn' => $request->get('guardian-msisdn'),
            'minor-relationship' => $request->get('minor-relationship'),
            'guardian-NIN' => $request->get('guardian-NIN'),
            'fingerCode' => $request->fingerCode,
            'fingerData' => $request->fingerData
        ];

        $request->session()->put('data', $body);

        return json_encode($body, 200);

        //return redirect('diplomat-registration-bulk2')->with('country', $this->getCountryList());
    }

    public function registerMinorSave_page1(KycRequest $request)
    {
        $body = [
            'guardian-msisdn' => $request->get('guardian-msisdn'),
            'minor-relationship' => $request->get('minor-relationship'),
            'guardian-NIN' => $request->get('guardian-NIN'),
            'fingerCode' => $request->fingerCode,
            'fingerData' => $request->fingerData
        ];

        $request->session()->put('data', $body);

        return json_encode($body, 200);
    }

    public function showDeRegisterPage1()
    {
        session()->forget(['previous-route', 'msisdn', 'PrimaryMsisdn']);
        return view('register.de-reg.de-register-page1');
    }

    public function saveDeRegisterPage1(Request $request)
    {
        $messages = [
            'NIN.required' => 'Please Input Customer\'s NIDA ID !',
            'NIN.digits' => 'Invalid Customer\'s NIDA ID Format !',
            'fingerCode.required' => 'Please Select Customer\'s finger index !',
            'fingerData.required' => 'Please Capture Customer\'s finger print !',
            'msisdn.required' => 'Please Input Customer\'s phone number!',
            'msisdn.regex' => 'Invalid Customer\'s phone number !',
        ];

        $this->validate($request, [
            'msisdn' => 'required|regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})/',
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ], $messages);

        $body = [
            'Msisdn' => $request->get('msisdn'),
            'NIN' => $request->get('NIN'),
            'FingerCode' => $request->fingerCode,
            'Fingerprints' => $request->fingerData,
            'platform' => 'web',
            'UserId' => $this->user['UserID']
        ];

        $client = new Client();

        $response = $client->request('POST', 'http://172.18.66.203:6070/api/Dereg', ['json' => $body]);

        $data = json_decode($response->getBody(), true);

        unset($body['Fingerprints']);

        Log::channel('De-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == '40') {
            return redirect()->back()->withErrors('Primary MSISDN ' . $request->get('msisdn') . ' Is not among the List of MSISDNs registered With NIN ' . $request->get('NIN'))->withInput();
        } elseif ($data['ID'] == '41') {
            return redirect()->back()->withErrors('An Internal Error Occured while fetching Customer MSISDNs from Icap')->withInput();
        } elseif ($data['ID'] == '42') {
            return redirect()->back()->withErrors('Customer MSISDNs Not Found With NIN ' . $request->get('NIN'))->withInput();
        } elseif ($data['ID'] == '0') {
            $list = explode(',', $data['Description']);
            session()->put(['previous-route' => Route::current()->getName(), 'msisdn' => $list, 'PrimaryMsisdn' => $request->get('msisdn')]);

            return redirect()->route('de-register2.show');
        } elseif ($data['ID'] !== '0') {
            return redirect()->back()->withErrors($data['Description'])->withInput();
        }

        return redirect()->back()->withErrors('Ooops ! Something Went Wrong !')->withInput();
    }

    public function showDeRegisterPage2()
    {
        if (Session::has('previous-route') && Session::get('previous-route') == 'de-register1.post') {
            Session::forget('previous-route');
            return view('register.de-reg.de-register-page2');
        } else {
            return redirect()->route('de-register1.show');
        }
    }

    public function saveDeRegisterPage2(Request $request)
    {
        $messages = [
            'msisdn.required' => 'Please Select Customer MSISDN to De-register !',
        ];

        $this->validate($request, [
            'msisdn' => 'required',
        ], $messages);

        $body = [
            'PrimaryMsisdn' => $request->primaryMsisdn,
            'MsisdnList' =>  $request->get('msisdn'),
            'platform' => 'web',
            'UserID' => $this->user['UserID']
        ];

        $client = new Client();

        $response = $client->request('POST', 'http://172.18.66.203:6070/api/DeregMsisdn', ['json' => $body]);

        $data = json_decode($response->getBody(), true);

        Log::channel('De-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            session()->put(['previous-route' => Route::current()->getName(), 'PrimaryMsisdn' => $request->primaryMsisdn]);
            return redirect()->route('de-register3.show');
        }

        return redirect()->back()->withErrors($data['Description'])->withInput();
    }

    public function showDeRegisterPage3()
    {

        if (Session::has('previous-route') && Session::get('previous-route') == 'de-register2.post') {
            Session::forget('previous-route');
            return view('register.de-reg.de-register-page3');
        } else {
            return redirect()->route('de-register1.show');
        }
    }

    public function saveDeRegisterPage3(Request $request)
    {
        $messages = [
            'otp.required' => 'Please Input OTP sent to Customer for Confirmation !',
            'deRegReason.required' => 'Please Select reason for Customer De-registration !',
        ];

        $this->validate($request, [
            'otp' => 'required',
            'deRegReason' => 'required',
        ], $messages);

        $body = [
            'OTP' => $request->get('otp'),
            'PrimaryMsisdn' => $request->primaryMsisdn,
            'Reason' => $request->deRegReason
        ];

        $client = new Client();

        $response = $client->request('POST', 'http://172.18.66.203:6070/api/VerifyDeregOTP', ['json' => $body]);

        $data = json_decode($response->getBody(), true);

        Log::channel('De-Reg')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        session()->forget(['previous-route', 'msisdn', 'PrimaryMsisdn']);

        if ($data['ID'] == 0) {
            return redirect()->route('home')->with('success', "Successful Customer Msisdn De-Registration !");
        } elseif ($data['ID'] == 21) {
            return redirect()->route('de-register1.show')->with('warning', "Failed Customer Msisdn De-Registration !");
        } elseif ($data['ID'] == 23) {
            return redirect()->route('de-register1.show')->with('warning', "Invalid OTP Received !");
        } elseif ($data['ID'] == 22 || $data['ID'] == 24) {
            return redirect()->route('de-register1.show')->with('warning', "Error from iCAP. Please dial *106# to comfirm De-registration !");
        }

        return redirect()->back()->withErrors($data['Description'])->withInput();
    }

    public function showPrimarySIMFirstPage()
    {
        session::forget(['msisdn', 'ID', 'NIN', 'previous-route']);
        return view('register.primary-sim.first-page');
    }

    public function postPrimarySIMFirstPage(Request $request)
    {
        $messages = [
            'NIN.required' => 'Please Input Customer\'s NIDA ID !',
            'NIN.digits' => 'Invalid Customer\'s NIDA ID Format !',
            'fingerCode.required' => 'Please Select Customer\'s finger index !',
            'fingerData.required' => 'Please Capture Customer\'s finger print !',
        ];

        $this->validate($request, [
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ], $messages);

        $body = [
            'NIN' => $request->get('NIN'),
            'FingerCode' => $request->fingerCode,
            'FingerData' => $request->fingerData,
            'platform' => 'web',
            'UserId' => $this->user['UserID']
        ];

        $url = 'GetMsisdnStatusWithNIN';

        $data = $this->postRequest($url, $body);

        unset($body['FingerData']);


        Log::channel('Primary-msisdn-first')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['NidaResponse'] == "01" || $data['NidaResponse'] == "141") {
            return response()->json([
                'message' => 'Your National Identification number have failed to be verified. Please retry !',
                'status' => $data['NidaResponse']
            ], 400);

            //return back()->withErrors('Your National Identification number have failed to be verified. Please retry !');
        } elseif ($data['NidaResponse'] == "132") {
            return response()->json([
                'message' => 'Customer NIDA number is not Found at NIDA. Try again !',
                'status' => $data['NidaResponse']
            ], 400);

            //return back()->withErrors('Customer NIDA number is not Found at NIDA. Try again !');
        } elseif ($data['NidaResponse'] == "2") {
            return response()->json([
                'message' => 'Something went wrong. Please try again !',
                'status' => $data['NidaResponse']
            ], 400);

            //return back()->withErrors('Something went wrong. Please try again !');
        } elseif ($data['NidaResponse'] == "99") {
            return response()->json([
                'message' => 'Your National Identification number has failed to be retrieved. Please try again later !',
                'status' => $data['NidaResponse']
            ], 400);

            //return back()->withErrors('Your National Identification number has failed to be retrieved. Please try again later !');
        } elseif ($data['NidaResponse'] == "0") {
            if ($data['Primary'] == null) {
                session()->put([
                    'previous-route' => Route::current()->getName(),
                    'msisdn' => $data['other'],
                    'ID' => $data['NidaTransctionID'],
                    'NIN' => $data['IDNumber']
                ]);

                return response()->json([
                    'message' => null,
                    'status' => $data['NidaResponse']
                ], 200);

                //return redirect()->route('primary-msisdn.second');
            } elseif (isset($data['Primary'])) {
                return response()->json([
                    'message' => 'You have already set primary number : ' . $data['Primary'],
                    'status' => $data['NidaResponse']
                ], 400);

                //return back()->with('warning', 'You have already set the primary number : ' .$data['Primary'] );
            }
        }

        return response()->json([
            'message' => 'Sorry, An error has occured !',
            'status' => $data['NidaResponse']
        ], 400);

        //return \redirect()->route('home')->with('warning', 'Sorry, An error has occured !');
    }

    public function showPrimarySIMSecondPage()
    {
        if (Session::has('previous-route') && Session::get('previous-route') == 'primary-msisdn.first.post') {
            $msisdnArray = explode(',', session::get('msisdn'));
            $msisdnArray = array_diff($msisdnArray, array(''));
            return view('register.primary-sim.second-page')->with([
                'msisdn' => $msisdnArray,
                'ID' =>  session::get('ID'),
                'NIN' =>  session::get('NIN')
            ]);
        }

        return redirect()->route('primary-msisdn.first');
    }

    public function postPrimarySIMSecondPage(Request $request)
    {
        $messages = [
            'primaryMsisdn.required' => 'Please Select Customer MSISDN to set as Primary MSISDN !',
        ];

        $this->validate($request, [
            'primaryMsisdn' => 'required',
        ], $messages);

        $body = [
            'Msisdn' => $request->primaryMsisdn,
            'IdNumber' =>  $request->NIN,
            'NidaTransctionID' => $request->ID,
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

            //return redirect()->route('home')->with('success', 'Successfully preset Primary MSISDN !');
        } elseif ($data['ID'] == 2) {
            return response()->json([
                'message' => 'Something went wrong. Please try again !',
                'status' => $data['ID']
            ], 400);
            //return redirect()->back()->withErrors('Something went wrong. Please try again !');
        } elseif ($data['ID'] == 1) {
            return response()->json([
                'message' => 'Customer has already set primary cell number !',
                'status' => $data['ID']
            ], 400);
            return redirect()->back()->withErrors('Customer has already set primary cell number !');
        }

        return response()->json([
            'message' => 'Sorry, An error has occured !',
            'status' => $data['ID']
        ], 200);
    }

    public function showSecondarySIMFirstPage()
    {
        session::forget(['msisdn', 'ID', 'NIN', 'previous-route', 'RegCategoryCode']);
        return view('register.secondary-sim.first-page');
    }

    public function postSecondarySIMFirstPage(Request $request)
    {
        $messages = [
            'NIN.required' => 'Please Input Customer\'s NIDA ID !',
            'NIN.digits' => 'Invalid Customer\'s NIDA ID Format !',
            'fingerCode.required' => 'Please Select Customer\'s finger index !',
            'fingerData.required' => 'Please Capture Customer\'s finger print !',
        ];

        $this->validate($request, [
            'NIN' => 'required | digits:20',
            'fingerCode' => 'required',
            'fingerData' => 'required'
        ], $messages);

        $body = [
            'NIN' => $request->get('NIN'),
            'FingerCode' => $request->fingerCode,
            'FingerData' => $request->fingerData,
            'platform' => 'web',
            'UserId' => $this->user['UserID']
        ];

        $url = 'GetMsisdnStatusForSecondaryNumber';

        $data = $this->postRequest($url, $body);

        unset($body['FingerData']);

        Log::channel('Secondary-msisdn-first')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['NidaResponse'] == 0) {
            if ($data['Primary'] == null) {
                return response()
                    ->json([
                        'message' => 'Please set Primary Msisdn before continuing !',
                        'status' => $data['Primary']
                    ], 400);
            } elseif ($data['isNinBlaclisted'] == 1) {
                return response()
                    ->json([
                        'message' => 'Customer NIN is Blacklisted by TCRA with reason : ' . $data['BlacklistReason'],
                        'status' => $data['isNinBlaclisted']
                    ], 400);
            } elseif (isset($data['Primary']) && $data['isNinBlaclisted'] == 0) {
                if ($data['other'] == null) {
                    return response()
                        ->json([
                            'message' => 'You have already have approvals for all msisdn !',
                            'status' => $data['Primary']
                        ], 400);
                } else {
                    session()->put([
                        'previous-route' => Route::current()->getName(),
                        'msisdn' => $data['other'],
                        'ID' => $data['NidaTransactionID'],
                        'NIN' => $data['IDNumber'],
                        'RegCategoryCode' => $data['RegCategoryCode']
                    ]);

                    return response()
                        ->json([
                            'message' => 'Continue !',
                            'status' => 0
                        ], 200);
                }
            }
        } elseif ($data['NidaResponse'] == "01" || $data['NidaResponse'] == "141") {
            return response()->json([
                'message' => 'Your National Identification number have failed to be verified. Please retry !',
                'status' => $data['NidaResponse']
            ], 400);

            //return back()->withErrors('Your National Identification number have failed to be verified. Please retry !');
        } elseif ($data['NidaResponse'] == "132") {
            return response()->json([
                'message' => 'Customer NIDA number is not Found at NIDA. Try again !',
                'status' => $data['NidaResponse']
            ], 400);
            //return back()->withErrors('Customer NIDA number is not Found at NIDA. Try again !');
        } elseif ($data['NidaResponse'] == "2") {
            return response()->json([
                'message' => 'Something went wrong. Please try again !',
                'status' => $data['NidaResponse']
            ], 400);

            //return back()->withErrors('Something went wrong. Please try again !');
        } elseif ($data['NidaResponse'] == "99") {
            return response()->json([
                'message' => 'Your National Identification number have failet to be retrieved. Please try again later !',
                'status' => $data['NidaResponse']
            ], 400);

            //return back()->withErrors('Your National Identification number have failet to be retrieved. Please try again later !');
        }

        return response()->json([
            'message' => 'Sorry, An error has occured !',
            'status' => $data['NidaResponse']
        ], 400);

        //return \redirect()->route('home')->with('danger', 'Sorry, An error has occured !');
    }

    public function showSecondarySIMSecondPage()
    {
        if (Session::has('previous-route') && Session::get('previous-route') == 'secondary-msisdn.first.post') {
            $msisdnArray = explode(',', session::get('msisdn'));
            $msisdnArray = array_diff($msisdnArray, array(''));
            return view('register.secondary-sim.second-page')->with([
                'msisdn' => $msisdnArray,
                'ID' =>  session::get('ID'),
                'NIN' =>  session::get('NIN'),
                'Code' =>  session::get('RegCategoryCode')
            ]);
        }

        return redirect()->route('secondary-msisdn.first');
    }

    public function postSecondarySIMSecondPage(Request $request)
    {
        $messages = [
            'tcraReason.required' => 'Please Select reason for seeking approval of secondary SIM number !',
            'secondaryMsisdn.required' => 'Please Select Customer MSISDN to set as secondary SIM number !',
        ];

        $this->validate($request, [
            'secondaryMsisdn' => 'required',
            'tcraReason' => 'required',
        ], $messages);

        $body = [
            'CustomerMsisdn' => $request->secondaryMsisdn,
            'CustomerNin' =>  $request->NIN,
            'NidaTransactionID' => $request->ID,
            'reasonCode' => $request->tcraReason,
            'registrationCategoryCode' => $request->Code,
            'UserID' => $this->user['UserID'],
        ];

        $url = 'DefineSecondaryMsisdn';

        $data = $this->postRequest($url, $body);

        Log::channel('Secondary-msisdn-second')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['TcraResponseCode'] == 151) {
            return response()->json([
                'message' => 'Customer NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 200);

            //return redirect()->route('home')->with('danger', 'Customer NIN is blacklisted by TCRA !');
        } elseif ($data['TcraResponseCode'] == 152) {

            return response()->json([
                'message' => 'Agent NIN is blacklisted by TCRA !',
                'status' => $data['TcraResponseCode']
            ], 200);
            //return redirect()->route('home')->with('danger', 'Agent NIN is blacklisted by TCRA !');
        } elseif ($data['TcraResponseCode'] == 153) {
            return response()->json([
                'message' => 'Customer has reached maximum SIM cards !',
                'status' => $data['TcraResponseCode']
            ], 200);
            //return  redirect()->route('home')->with('warning', 'Customer has reached maximum SIM cards !');
        } elseif ($data['TcraResponseCode'] == 154) {
            return response()->json([
                'message' => 'Customer reason not accepted by TCRA. Please choose another !',
                'status' => $data['TcraResponseCode']
            ], 400);
            //return back()->withErrors('Customer reason not accepted by TCRA. Please choose another !');
        } elseif ($data['TcraResponseCode'] == 156) {
            return response()->json([
                'message' => 'Duplicate customer msisdn from TCRA !',
                'status' => $data['TcraResponseCode']
            ], 400);
        } elseif ($data['TcraResponseCode'] == 4) {
            return response()->json([
                'message' => 'You are not Authorised to access this page !',
                'status' => $data['TcraResponseCode']
            ], 200);

            //return  redirect()->route('home')->with('warning','You are not Authorised to access this page !');
        } elseif ($data['TcraResponseCode'] == 150) {
            if ($data['IcapResponseCode'] == 0) {
                return response()->json([
                    'message' => 'Successfully set Secondary MSISDN !',
                    'status' => $data['TcraResponseCode']
                ], 200);
                //return redirect()->route('home')->with('success', 'Successfully set Secondary MSISDN !');
            }
        }

        return response()->json([
            'message' => 'Sorry, An error has occured !',
            'status' => '999'
        ], 200);

        //return  redirect()->route('home')->with('danger', 'Sorry, An error has occured !');
    }

    public function viewPrimaryMsisdnOtherFirst()
    {
        return view('register.primary-sim.primary-other-first');
    }

    public function getListPrimaryMsisdnOther(Request $request)
    {
        $messages = [
            'customerID.required' => 'Please input customer ID number !'
        ];

        $this->validate($request, [
            'customerID' => 'required'
        ], $messages);

        $body = [
            'IDNumber' => $request->customerID,
            'UserID' => (int) $this->user['UserID']
        ];

        $url = 'GetMsisdnListForOtherID';

        $data = $this->postRequest($url, $body);

        Log::channel('Primary-msisdn-other-first')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['isNinBlaclisted'] == 1) {
            return response()->json(['message' => 'Customer NIN is blacklisted with reason: ' . $data['BlacklistReason'], 'status' => $data['isNinBlaclisted']], 400);
        } elseif (isset($data['Primary'])) {
            return response()->json(['message' => 'Customer has already set Primary msisdn : ' . $data['Primary'], 'status' => $data['Primary']], 400);
        } elseif (!isset($data['other'])) {
            return response()->json(['message' => 'Customer does not have any msisdn registered', 'status' => $data['other']], 400);
        } elseif ($data['Primary'] == null && isset($data['other'])) {
            $request->session()->put(['customerID' => $request->customerID, 'msisdn' => $data['other'], 'previous-route' => Route::current()->getName(),]);
            return response()->json(['message' => null, 'status' => null], 200);
        }

        return response()->json(['message' => 'Sorry, An error has occured !', 'status' => '999'], 400);
    }

    public function viewPrimaryMsisdnOtherSecond()
    {
        if (Session::has('previous-route') && Session::get('previous-route') == 'primary-msisdn.other.first.post') {
            $msisdnArray = explode(',', session::get('msisdn'));
            $msisdnArray = array_diff($msisdnArray, array(''));
            return view('register.primary-sim.primary-other-second')->with([
                'msisdn' => $msisdnArray,
                'ID' =>  session::get('customerID'),
            ]);
        }
    }

    public function setPrimaryMsisdnOther(Request $request)
    {
        $messages = [
            'primaryMsisdn.required' => 'Please select customer primary number from the list !'
        ];

        $this->validate($request, [
            'primaryMsisdn' => 'required'
        ], $messages);

        $body = [
            'IdNumber' => $request->customerID,
            'Msisdn' => $request->primaryMsisdn,
            'UserID' => (int) $this->user['UserID']
        ];

        $url = 'DefinePrimaryNumberForOtherIDs';

        $data = $this->postRequest($url, $body);

        Log::channel('Primary-msisdn-other-second')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] == 0) {
            $request->session()->forget(['previous-route', 'msisdn', 'customerID']);
            return response()->json(['message' => 'Successfully preset Primary MSISDN !', 'status' => $data['ID']], 200);
        } elseif ($data['ID'] == 2) {
            return response()->json(['message' => 'Something went wrong. Please try again !', 'status' => $data['ID']], 400);
        } elseif ($data['ID'] == 1) {
            return response()->json(['message' => 'Customer has already set primary cell number !', 'status' => $data['ID']], 400);
        }

        return response()->json(['message' => 'Sorry, An error has occured !', 'status' => $data['ID']], 200);
    }

    public function viewSecondaryMsisdnOtherFirst()
    {
        return view('register.secondary-sim.secondary-other-first');
    }

    public function getListSecondaryMsisdnOther(Request $request)
    {
        $messages = [
            'customerID.required' => 'Please input customer ID number !'
        ];

        $this->validate($request, [
            'customerID' => 'required'
        ], $messages);

        $body = [
            'IDNumber' => $request->customerID,
            'UserID' => (int) $this->user['UserID']
        ];

        $url = 'GetMsisdnListForOtherID';

        $data = $this->postRequest($url, $body);

        Log::channel('Secondary-msisdn-other-first')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['isNinBlaclisted'] == 1) {
            return response()->json(['message' => 'Customer NIN is blacklisted with reason: ' . $data['BlacklistReason'], 'status' => $data['isNinBlaclisted']], 400);
        } elseif (!isset($data['Primary'])) {
            return response()->json(['message' => 'Customer has not set Primary msisdn ! ', 'status' => $data['Primary']], 400);
        } elseif (!isset($data['other'])) {
            return response()->json(['message' => 'Customer has already set all msisdn', 'status' => $data['other']], 400);
        } elseif ($data['Primary'] !== null && isset($data['other'])) {
            $request->session()->put(['customerID' => $request->customerID, 'msisdn' => $data['other'], 'previous-route' => Route::current()->getName(),]);
            return response()->json(['message' => null, 'status' => null], 200);
        }

        return response()->json(['message' => 'Sorry, An error has occured !', 'status' => '999'], 400);
    }

    public function viewSecondaryMsisdnOtherSecond()
    {
        if (Session::has('previous-route') && Session::get('previous-route') == 'secondary-msisdn.other.first.post') {
            $msisdnArray = explode(',', session::get('msisdn'));
            $msisdnArray = array_diff($msisdnArray, array(''));
            return view('register.secondary-sim.secondary-other-second')->with([
                'msisdn' => $msisdnArray,
                'ID' =>  session::get('customerID'),
            ]);
        }
    }

    public function setSecondaryMsisdnOther(Request $request)
    {
        $messages = [
            'secondaryMsisdn.required' => 'Please select customer secondary number from the list !',
            'tcraReason.required' => 'Please Select reason for seeking approval of secondary SIM number !',
            'categoryCode.required' => 'Please Select registration category !',
        ];

        $this->validate($request, [
            'secondaryMsisdn' => 'required',
            'tcraReason' => 'required',
            'categoryCode' => 'required',
        ], $messages);

        $body = [
            'CustomerID' => $request->customerID,
            'CustomerMsisdn' => $request->secondaryMsisdn,
            'reasonCode' => $request->tcraReason,
            'registrationCategoryCode' => $request->categoryCode,
            'UserID' => (int) $this->user['UserID']
        ];

        $url = 'DefineSecondaryMsisdnForOtherID';

        $data = $this->postRequest($url, $body);

        Log::channel('Secondary-msisdn-other-second')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        return response()->json($data, 200);

        if ($data['ID'] == 0) {
            $request->session()->forget(['previous-route', 'msisdn', 'customerID']);
            return response()->json(['message' => 'Successfully preset Primary MSISDN !', 'status' => $data['ID']], 200);
        } elseif ($data['ID'] == 2) {
            return response()->json(['message' => 'Something went wrong. Please try again !', 'status' => $data['ID']], 400);
        } elseif ($data['ID'] == 1) {
            return response()->json(['message' => 'Customer has already set primary cell number !', 'status' => $data['ID']], 400);
        }

        return response()->json(['message' => 'Sorry, An error has occured !', 'status' => $data['ID']], 200);
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

    private function getCountryList()
    {
        return  array(0 => array('Code' => 'AF', 'Name' => 'Afghanistan',), 1 => array('Code' => 'AX', 'Name' => 'Åland Islands',), 2 => array('Code' => 'AL', 'Name' => 'Albania',), 3 => array('Code' => 'DZ', 'Name' => 'Algeria',), 4 => array('Code' => 'AS', 'Name' => 'American Samoa',), 5 => array('Code' => 'AD', 'Name' => 'Andorra',), 6 => array('Code' => 'AO', 'Name' => 'Angola',), 7 => array('Code' => 'AI', 'Name' => 'Anguilla',), 8 => array('Code' => 'AQ', 'Name' => 'Antarctica',), 9 => array('Code' => 'AG', 'Name' => 'Antigua and Barbuda',), 10 => array('Code' => 'AR', 'Name' => 'Argentina',), 11 => array('Code' => 'AM', 'Name' => 'Armenia',), 12 => array('Code' => 'AW', 'Name' => 'Aruba',), 13 => array('Code' => 'AU', 'Name' => 'Australia',), 14 => array('Code' => 'AT', 'Name' => 'Austria',), 15 => array('Code' => 'AZ', 'Name' => 'Azerbaijan',), 16 => array('Code' => 'BS', 'Name' => 'Bahamas',), 17 => array('Code' => 'BH', 'Name' => 'Bahrain',), 18 => array('Code' => 'BD', 'Name' => 'Bangladesh',), 19 => array('Code' => 'BB', 'Name' => 'Barbados',), 20 => array('Code' => 'BY', 'Name' => 'Belarus',), 21 => array('Code' => 'BE', 'Name' => 'Belgium',), 22 => array('Code' => 'BZ', 'Name' => 'Belize',), 23 => array('Code' => 'BJ', 'Name' => 'Benin',), 24 => array('Code' => 'BM', 'Name' => 'Bermuda',), 25 => array('Code' => 'BT', 'Name' => 'Bhutan',), 26 => array('Code' => 'BO', 'Name' => 'Bolivia, Plurinational State of',), 27 => array('Code' => 'BQ', 'Name' => 'Bonaire, Sint Eustatius and Saba',), 28 => array('Code' => 'BA', 'Name' => 'Bosnia and Herzegovina',), 29 => array('Code' => 'BW', 'Name' => 'Botswana',), 30 => array('Code' => 'BV', 'Name' => 'Bouvet Island',), 31 => array('Code' => 'BR', 'Name' => 'Brazil',), 32 => array('Code' => 'IO', 'Name' => 'British Indian Ocean Territory',), 33 => array('Code' => 'BN', 'Name' => 'Brunei Darussalam',), 34 => array('Code' => 'BG', 'Name' => 'Bulgaria',), 35 => array('Code' => 'BF', 'Name' => 'Burkina Faso',), 36 => array('Code' => 'BI', 'Name' => 'Burundi',), 37 => array('Code' => 'KH', 'Name' => 'Cambodia',), 38 => array('Code' => 'CM', 'Name' => 'Cameroon',), 39 => array('Code' => 'CA', 'Name' => 'Canada',), 40 => array('Code' => 'CV', 'Name' => 'Cape Verde',), 41 => array('Code' => 'KY', 'Name' => 'Cayman Islands',), 42 => array('Code' => 'CF', 'Name' => 'Central African Republic',), 43 => array('Code' => 'TD', 'Name' => 'Chad',), 44 => array('Code' => 'CL', 'Name' => 'Chile',), 45 => array('Code' => 'CN', 'Name' => 'China',), 46 => array('Code' => 'CX', 'Name' => 'Christmas Island',), 47 => array('Code' => 'CC', 'Name' => 'Cocos (Keeling) Islands',), 48 => array('Code' => 'CO', 'Name' => 'Colombia',), 49 => array('Code' => 'KM', 'Name' => 'Comoros',), 50 => array('Code' => 'CG', 'Name' => 'Congo',), 51 => array('Code' => 'CD', 'Name' => 'Congo, the Democratic Republic of the',), 52 => array('Code' => 'CK', 'Name' => 'Cook Islands',), 53 => array('Code' => 'CR', 'Name' => 'Costa Rica',), 54 => array('Code' => 'CI', 'Name' => 'Côte d\'Ivoire',), 55 => array('Code' => 'HR', 'Name' => 'Croatia',), 56 => array('Code' => 'CU', 'Name' => 'Cuba',), 57 => array('Code' => 'CW', 'Name' => 'Curaçao',), 58 => array('Code' => 'CY', 'Name' => 'Cyprus',), 59 => array('Code' => 'CZ', 'Name' => 'Czech Republic',), 60 => array('Code' => 'DK', 'Name' => 'Denmark',), 61 => array('Code' => 'DJ', 'Name' => 'Djibouti',), 62 => array('Code' => 'DM', 'Name' => 'Dominica',), 63 => array('Code' => 'DO', 'Name' => 'Dominican Republic',), 64 => array('Code' => 'EC', 'Name' => 'Ecuador',), 65 => array('Code' => 'EG', 'Name' => 'Egypt',), 66 => array('Code' => 'SV', 'Name' => 'El Salvador',), 67 => array('Code' => 'GQ', 'Name' => 'Equatorial Guinea',), 68 => array('Code' => 'ER', 'Name' => 'Eritrea',), 69 => array('Code' => 'EE', 'Name' => 'Estonia',), 70 => array('Code' => 'ET', 'Name' => 'Ethiopia',), 71 => array('Code' => 'FK', 'Name' => 'Falkland Islands (Malvinas)',), 72 => array('Code' => 'FO', 'Name' => 'Faroe Islands',), 73 => array('Code' => 'FJ', 'Name' => 'Fiji',), 74 => array('Code' => 'FI', 'Name' => 'Finland',), 75 => array('Code' => 'FR', 'Name' => 'France',), 76 => array('Code' => 'GF', 'Name' => 'French Guiana',), 77 => array('Code' => 'PF', 'Name' => 'French Polynesia',), 78 => array('Code' => 'TF', 'Name' => 'French Southern Territories',), 79 => array('Code' => 'GA', 'Name' => 'Gabon',), 80 => array('Code' => 'GM', 'Name' => 'Gambia',), 81 => array('Code' => 'GE', 'Name' => 'Georgia',), 82 => array('Code' => 'DE', 'Name' => 'Germany',), 83 => array('Code' => 'GH', 'Name' => 'Ghana',), 84 => array('Code' => 'GI', 'Name' => 'Gibraltar',), 85 => array('Code' => 'GR', 'Name' => 'Greece',), 86 => array('Code' => 'GL', 'Name' => 'Greenland',), 87 => array('Code' => 'GD', 'Name' => 'Grenada',), 88 => array('Code' => 'GP', 'Name' => 'Guadeloupe',), 89 => array('Code' => 'GU', 'Name' => 'Guam',), 90 => array('Code' => 'GT', 'Name' => 'Guatemala',), 91 => array('Code' => 'GG', 'Name' => 'Guernsey',), 92 => array('Code' => 'GN', 'Name' => 'Guinea',), 93 => array('Code' => 'GW', 'Name' => 'Guinea-Bissau',), 94 => array('Code' => 'GY', 'Name' => 'Guyana',), 95 => array('Code' => 'HT', 'Name' => 'Haiti',), 96 => array('Code' => 'HM', 'Name' => 'Heard Island and McDonald Islands',), 97 => array('Code' => 'VA', 'Name' => 'Holy See (Vatican City State)',), 98 => array('Code' => 'HN', 'Name' => 'Honduras',), 99 => array('Code' => 'HK', 'Name' => 'Hong Kong',), 100 => array('Code' => 'HU', 'Name' => 'Hungary',), 101 => array('Code' => 'IS', 'Name' => 'Iceland',), 102 => array('Code' => 'IN', 'Name' => 'India',), 103 => array('Code' => 'ID', 'Name' => 'Indonesia',), 104 => array('Code' => 'IR', 'Name' => 'Iran, Islamic Republic of',), 105 => array('Code' => 'IQ', 'Name' => 'Iraq',), 106 => array('Code' => 'IE', 'Name' => 'Ireland',), 107 => array('Code' => 'IM', 'Name' => 'Isle of Man',), 108 => array('Code' => 'IL', 'Name' => 'Israel',), 109 => array('Code' => 'IT', 'Name' => 'Italy',), 110 => array('Code' => 'JM', 'Name' => 'Jamaica',), 111 => array('Code' => 'JP', 'Name' => 'Japan',), 112 => array('Code' => 'JE', 'Name' => 'Jersey',), 113 => array('Code' => 'JO', 'Name' => 'Jordan',), 114 => array('Code' => 'KZ', 'Name' => 'Kazakhstan',), 115 => array('Code' => 'KE', 'Name' => 'Kenya',), 116 => array('Code' => 'KI', 'Name' => 'Kiribati',), 117 => array('Code' => 'KP', 'Name' => 'Korea, Democratic People\'s Republic of',), 118 => array('Code' => 'KR', 'Name' => 'Korea, Republic of',), 119 => array('Code' => 'KW', 'Name' => 'Kuwait',), 120 => array('Code' => 'KG', 'Name' => 'Kyrgyzstan',), 121 => array('Code' => 'LA', 'Name' => 'Lao People\'s Democratic Republic',), 122 => array('Code' => 'LV', 'Name' => 'Latvia',), 123 => array('Code' => 'LB', 'Name' => 'Lebanon',), 124 => array('Code' => 'LS', 'Name' => 'Lesotho',), 125 => array('Code' => 'LR', 'Name' => 'Liberia',), 126 => array('Code' => 'LY', 'Name' => 'Libya',), 127 => array('Code' => 'LI', 'Name' => 'Liechtenstein',), 128 => array('Code' => 'LT', 'Name' => 'Lithuania',), 129 => array('Code' => 'LU', 'Name' => 'Luxembourg',), 130 => array('Code' => 'MO', 'Name' => 'Macao',), 131 => array('Code' => 'MK', 'Name' => 'Macedonia, the Former Yugoslav Republic of',), 132 => array('Code' => 'MG', 'Name' => 'Madagascar',), 133 => array('Code' => 'MW', 'Name' => 'Malawi',), 134 => array('Code' => 'MY', 'Name' => 'Malaysia',), 135 => array('Code' => 'MV', 'Name' => 'Maldives',), 136 => array('Code' => 'ML', 'Name' => 'Mali',), 137 => array('Code' => 'MT', 'Name' => 'Malta',), 138 => array('Code' => 'MH', 'Name' => 'Marshall Islands',), 139 => array('Code' => 'MQ', 'Name' => 'Martinique',), 140 => array('Code' => 'MR', 'Name' => 'Mauritania',), 141 => array('Code' => 'MU', 'Name' => 'Mauritius',), 142 => array('Code' => 'YT', 'Name' => 'Mayotte',), 143 => array('Code' => 'MX', 'Name' => 'Mexico',), 144 => array('Code' => 'FM', 'Name' => 'Micronesia, Federated States of',), 145 => array('Code' => 'MD', 'Name' => 'Moldova, Republic of',), 146 => array('Code' => 'MC', 'Name' => 'Monaco',), 147 => array('Code' => 'MN', 'Name' => 'Mongolia',), 148 => array('Code' => 'ME', 'Name' => 'Montenegro',), 149 => array('Code' => 'MS', 'Name' => 'Montserrat',), 150 => array('Code' => 'MA', 'Name' => 'Morocco',), 151 => array('Code' => 'MZ', 'Name' => 'Mozambique',), 152 => array('Code' => 'MM', 'Name' => 'Myanmar',), 153 => array('Code' => 'NA', 'Name' => 'Namibia',), 154 => array('Code' => 'NR', 'Name' => 'Nauru',), 155 => array('Code' => 'NP', 'Name' => 'Nepal',), 156 => array('Code' => 'NL', 'Name' => 'Netherlands',), 157 => array('Code' => 'NC', 'Name' => 'New Caledonia',), 158 => array('Code' => 'NZ', 'Name' => 'New Zealand',), 159 => array('Code' => 'NI', 'Name' => 'Nicaragua',), 160 => array('Code' => 'NE', 'Name' => 'Niger',), 161 => array('Code' => 'NG', 'Name' => 'Nigeria',), 162 => array('Code' => 'NU', 'Name' => 'Niue',), 163 => array('Code' => 'NF', 'Name' => 'Norfolk Island',), 164 => array('Code' => 'MP', 'Name' => 'Northern Mariana Islands',), 165 => array('Code' => 'NO', 'Name' => 'Norway',), 166 => array('Code' => 'OM', 'Name' => 'Oman',), 167 => array('Code' => 'PK', 'Name' => 'Pakistan',), 168 => array('Code' => 'PW', 'Name' => 'Palau',), 169 => array('Code' => 'PS', 'Name' => 'Palestine, State of',), 170 => array('Code' => 'PA', 'Name' => 'Panama',), 171 => array('Code' => 'PG', 'Name' => 'Papua New Guinea',), 172 => array('Code' => 'PY', 'Name' => 'Paraguay',), 173 => array('Code' => 'PE', 'Name' => 'Peru',), 174 => array('Code' => 'PH', 'Name' => 'Philippines',), 175 => array('Code' => 'PN', 'Name' => 'Pitcairn',), 176 => array('Code' => 'PL', 'Name' => 'Poland',), 177 => array('Code' => 'PT', 'Name' => 'Portugal',), 178 => array('Code' => 'PR', 'Name' => 'Puerto Rico',), 179 => array('Code' => 'QA', 'Name' => 'Qatar',), 180 => array('Code' => 'RE', 'Name' => 'Réunion',), 181 => array('Code' => 'RO', 'Name' => 'Romania',), 182 => array('Code' => 'RU', 'Name' => 'Russian Federation',), 183 => array('Code' => 'RW', 'Name' => 'Rwanda',), 184 => array('Code' => 'BL', 'Name' => 'Saint Barthélemy',), 185 => array('Code' => 'SH', 'Name' => 'Saint Helena, Ascension and Tristan da Cunha',), 186 => array('Code' => 'KN', 'Name' => 'Saint Kitts and Nevis',), 187 => array('Code' => 'LC', 'Name' => 'Saint Lucia',), 188 => array('Code' => 'MF', 'Name' => 'Saint Martin (French part)',), 189 => array('Code' => 'PM', 'Name' => 'Saint Pierre and Miquelon',), 190 => array('Code' => 'VC', 'Name' => 'Saint Vincent and the Grenadines',), 191 => array('Code' => 'WS', 'Name' => 'Samoa',), 192 => array('Code' => 'SM', 'Name' => 'San Marino',), 193 => array('Code' => 'ST', 'Name' => 'Sao Tome and Principe',), 194 => array('Code' => 'SA', 'Name' => 'Saudi Arabia',), 195 => array('Code' => 'SN', 'Name' => 'Senegal',), 196 => array('Code' => 'RS', 'Name' => 'Serbia',), 197 => array('Code' => 'SC', 'Name' => 'Seychelles',), 198 => array('Code' => 'SL', 'Name' => 'Sierra Leone',), 199 => array('Code' => 'SG', 'Name' => 'Singapore',), 200 => array('Code' => 'SX', 'Name' => 'Sint Maarten (Dutch part)',), 201 => array('Code' => 'SK', 'Name' => 'Slovakia',), 202 => array('Code' => 'SI', 'Name' => 'Slovenia',), 203 => array('Code' => 'SB', 'Name' => 'Solomon Islands',), 204 => array('Code' => 'SO', 'Name' => 'Somalia',), 205 => array('Code' => 'ZA', 'Name' => 'South Africa',), 206 => array('Code' => 'GS', 'Name' => 'South Georgia and the South Sandwich Islands',), 207 => array('Code' => 'SS', 'Name' => 'South Sudan',), 208 => array('Code' => 'ES', 'Name' => 'Spain',), 209 => array('Code' => 'LK', 'Name' => 'Sri Lanka',), 210 => array('Code' => 'SD', 'Name' => 'Sudan',), 211 => array('Code' => 'SR', 'Name' => 'Suriname',), 212 => array('Code' => 'SJ', 'Name' => 'Svalbard and Jan Mayen',), 213 => array('Code' => 'SZ', 'Name' => 'Swaziland',), 214 => array('Code' => 'SE', 'Name' => 'Sweden',), 215 => array('Code' => 'CH', 'Name' => 'Switzerland',), 216 => array('Code' => 'SY', 'Name' => 'Syrian Arab Republic',), 217 => array('Code' => 'TW', 'Name' => 'Taiwan, Province of China',), 218 => array('Code' => 'TJ', 'Name' => 'Tajikistan',), 219 => array('Code' => 'TZ', 'Name' => 'Tanzania, United Republic of',), 220 => array('Code' => 'TH', 'Name' => 'Thailand',), 221 => array('Code' => 'TL', 'Name' => 'Timor-Leste',), 222 => array('Code' => 'TG', 'Name' => 'Togo',), 223 => array('Code' => 'TK', 'Name' => 'Tokelau',), 224 => array('Code' => 'TO', 'Name' => 'Tonga',), 225 => array('Code' => 'TT', 'Name' => 'Trinidad and Tobago',), 226 => array('Code' => 'TN', 'Name' => 'Tunisia',), 227 => array('Code' => 'TR', 'Name' => 'Turkey',), 228 => array('Code' => 'TM', 'Name' => 'Turkmenistan',), 229 => array('Code' => 'TC', 'Name' => 'Turks and Caicos Islands',), 230 => array('Code' => 'TV', 'Name' => 'Tuvalu',), 231 => array('Code' => 'UG', 'Name' => 'Uganda',), 232 => array('Code' => 'UA', 'Name' => 'Ukraine',), 233 => array('Code' => 'AE', 'Name' => 'United Arab Emirates',), 234 => array('Code' => 'GB', 'Name' => 'United Kingdom',), 235 => array('Code' => 'US', 'Name' => 'United States',), 236 => array('Code' => 'UM', 'Name' => 'United States Minor Outlying Islands',), 237 => array('Code' => 'UY', 'Name' => 'Uruguay',), 238 => array('Code' => 'UZ', 'Name' => 'Uzbekistan',), 239 => array('Code' => 'VU', 'Name' => 'Vanuatu',), 240 => array('Code' => 'VE', 'Name' => 'Venezuela, Bolivarian Republic of',), 241 => array('Code' => 'VN', 'Name' => 'Viet Nam',), 242 => array('Code' => 'VG', 'Name' => 'Virgin Islands, British',), 243 => array('Code' => 'VI', 'Name' => 'Virgin Islands, U.S.',), 244 => array('Code' => 'WF', 'Name' => 'Wallis and Futuna',), 245 => array('Code' => 'EH', 'Name' => 'Western Sahara',), 246 => array('Code' => 'YE', 'Name' => 'Yemen',), 247 => array('Code' => 'ZM', 'Name' => 'Zambia',), 248 => array('Code' => 'ZW', 'Name' => 'Zimbabwe',),);
    }

    private function ImmigrationCountryList()
    {
        return [
            ['COUNTRY' => 'AFGHANISTAN', 'ABBREVIATION' => 'AFG'], ['COUNTRY' => 'ALBANIA', 'ABBREVIATION' => 'ALB'], ['COUNTRY' => 'ALGERIA', 'ABBREVIATION' => 'DZA'], ['COUNTRY' => 'AMERICANSAMOA', 'ABBREVIATION' => 'ASM'], ['COUNTRY' => 'ANDORRA', 'ABBREVIATION' => 'AND'], ['COUNTRY' => 'ANGOLA', 'ABBREVIATION' => 'AGO'], ['COUNTRY' => 'ANGUILLA', 'ABBREVIATION' => 'AIA'], ['COUNTRY' => 'ANTARTICA', 'ABBREVIATION' => 'ATA'], ['COUNTRY' => 'ANTIGUAANDBARBUDA', 'ABBREVIATION' => 'ATG'], ['COUNTRY' => 'ARGENTINA', 'ABBREVIATION' => 'ARG'], ['COUNTRY' => 'ARMENIA', 'ABBREVIATION' => 'ARM'], ['COUNTRY' => 'ARUBA', 'ABBREVIATION' => 'ABW'], ['COUNTRY' => 'AUSTRALIA', 'ABBREVIATION' => 'AUS'], ['COUNTRY' => 'AUSTRIA', 'ABBREVIATION' => 'AUT'], ['COUNTRY' => 'AZERBAIJAN', 'ABBREVIATION' => 'AZE'], ['COUNTRY' => 'BAHAMAS', 'ABBREVIATION' => 'BHS'], ['COUNTRY' => 'BAHRAIN', 'ABBREVIATION' => 'BHR'], ['COUNTRY' => 'BANGLADESH', 'ABBREVIATION' => 'BGD'], ['COUNTRY' => 'BARBADOS', 'ABBREVIATION' => 'BRB'], ['COUNTRY' => 'BELARUS', 'ABBREVIATION' => 'BLR'], ['COUNTRY' => 'BELGIUM', 'ABBREVIATION' => 'BEL'], ['COUNTRY' => 'BELIZE', 'ABBREVIATION' => 'BLZ'], ['COUNTRY' => 'BENIN', 'ABBREVIATION' => 'BEN'], ['COUNTRY' => 'BERMUDA', 'ABBREVIATION' => 'BMU'], ['COUNTRY' => 'BHUTAN', 'ABBREVIATION' => 'BTN'], ['COUNTRY' => 'BOLIVIA', 'ABBREVIATION' => 'BOL'], ['COUNTRY' => 'BOSNIAANDHERZEGOWINA', 'ABBREVIATION' => 'BIH'], ['COUNTRY' => 'BOTSWANA', 'ABBREVIATION' => 'BWA'], ['COUNTRY' => 'BOUVETISLAND', 'ABBREVIATION' => 'BVT'], ['COUNTRY' => 'BRAZIL', 'ABBREVIATION' => 'BRA'], ['COUNTRY' => 'BRITISHINDIANOCEANTERRITORY', 'ABBREVIATION' => 'IOT'], ['COUNTRY' => 'BRUNEIDARUSSALAM', 'ABBREVIATION' => 'BRN'], ['COUNTRY' => 'BULGARIA', 'ABBREVIATION' => 'BGR'], ['COUNTRY' => 'BURKINAFASO', 'ABBREVIATION' => 'BFA'], ['COUNTRY' => 'BURUNDI', 'ABBREVIATION' => 'BDI'], ['COUNTRY' => 'CAMBODIA', 'ABBREVIATION' => 'KHM'], ['COUNTRY' => 'CAMEROON', 'ABBREVIATION' => 'CMR'], ['COUNTRY' => 'CANADA', 'ABBREVIATION' => 'CAN'], ['COUNTRY' => 'CAPEVERDE', 'ABBREVIATION' => 'CPV'], ['COUNTRY' => 'CAYMANISLANDS', 'ABBREVIATION' => 'CYM'], ['COUNTRY' => 'CENTRALAFRICANREPUBLIC', 'ABBREVIATION' => 'CAF'], ['COUNTRY' => 'CHAD', 'ABBREVIATION' => 'TCD'], ['COUNTRY' => 'CHILE', 'ABBREVIATION' => 'CHL'], ['COUNTRY' => 'CHINA', 'ABBREVIATION' => 'CHN'], ['COUNTRY' => 'CHRISTMASISLAND', 'ABBREVIATION' => 'CXR'], ['COUNTRY' => 'COCOS(KEELING)ISLANDS', 'ABBREVIATION' => 'CCK'], ['COUNTRY' => 'COLOMBIA', 'ABBREVIATION' => 'COL'], ['COUNTRY' => 'COMOROS', 'ABBREVIATION' => 'COM'], ['COUNTRY' => 'CONGODEMOCRATICREPUBLIC(ZAIRE)', 'ABBREVIATION' => 'COD',], ['COUNTRY' => 'CONGOPEOPLE\'SREPUBLIC', 'ABBREVIATION' => 'COG'], ['COUNTRY' => 'COOKISLANDS', 'ABBREVIATION' => 'COK'], ['COUNTRY' => 'COSTARICA', 'ABBREVIATION' => 'CRI'], ['COUNTRY' => 'COTED\'IVOIRE', 'ABBREVIATION' => 'CIV'], ['COUNTRY' => 'CROATIA(HRVATSKA)', 'ABBREVIATION' => 'HRV'], ['COUNTRY' => 'CUBA', 'ABBREVIATION' => 'CUB'], ['COUNTRY' => 'CYPRUS', 'ABBREVIATION' => 'CYP'], ['COUNTRY' => 'CZECHREPUBLIC', 'ABBREVIATION' => 'CZE'], ['COUNTRY' => 'DENMARK', 'ABBREVIATION' => 'DNK'], ['COUNTRY' => 'DJIBOUTI', 'ABBREVIATION' => 'DJI'], ['COUNTRY' => 'DOMINICA', 'ABBREVIATION' => 'DMA'], ['COUNTRY' => 'DOMINICANREPUBLIC', 'ABBREVIATION' => 'DOM'], ['COUNTRY' => 'EASTTIMOR', 'ABBREVIATION' => 'TLS'], ['COUNTRY' => 'ECUADOR', 'ABBREVIATION' => 'ECU'], ['COUNTRY' => 'EGYPT', 'ABBREVIATION' => 'EGY'], ['COUNTRY' => 'ELSALVADOR', 'ABBREVIATION' => 'SLV'], ['COUNTRY' => 'EQUATORIALGUINEA', 'ABBREVIATION' => 'GNQ'], ['COUNTRY' => 'ERITREA', 'ABBREVIATION' => 'ERI'], ['COUNTRY' => 'ESTONIA', 'ABBREVIATION' => 'EST'], ['COUNTRY' => 'ETHIOPIA', 'ABBREVIATION' => 'ETH'], ['COUNTRY' => 'FALKLANDISLANDS(MALVINAS)', 'ABBREVIATION' => 'FLK'], ['COUNTRY' => 'FAROEISLANDS', 'ABBREVIATION' => 'FRO'], ['COUNTRY' => 'FIJI', 'ABBREVIATION' => 'FJI'], ['COUNTRY' => 'FINLAND', 'ABBREVIATION' => 'FIN'], ['COUNTRY' => 'FRANCE', 'ABBREVIATION' => 'FRA'], ['COUNTRY' => 'FRENCHGUIANA', 'ABBREVIATION' => 'GUF'], ['COUNTRY' => 'FRENCHPOLYNESIA', 'ABBREVIATION' => 'PYF'], ['COUNTRY' => 'FRENCHSOUTHERNANDANTARCTICLANDS', 'ABBREVIATION' => 'ATF'], ['COUNTRY' => 'GABON', 'ABBREVIATION' => 'GAB'], ['COUNTRY' => 'GAMBIA', 'ABBREVIATION' => 'GMB'], ['COUNTRY' => 'GEORGIA', 'ABBREVIATION' => 'GEO'], ['COUNTRY' => 'GERMANY', 'ABBREVIATION' => 'DEU'], ['COUNTRY' => 'GHANA', 'ABBREVIATION' => 'GHA'], ['COUNTRY' => 'GIBRALTAR', 'ABBREVIATION' => 'GIB'], ['COUNTRY' => 'GREECE', 'ABBREVIATION' => 'GRC'], ['COUNTRY' => 'GREENLAND', 'ABBREVIATION' => 'GRL'], ['COUNTRY' => 'GRENADA', 'ABBREVIATION' => 'GRD'], ['COUNTRY' => 'GUADELOUPE', 'ABBREVIATION' => 'GLP'], ['COUNTRY' => 'GUAM', 'ABBREVIATION' => 'GUM'], ['COUNTRY' => 'GUATEMALA', 'ABBREVIATION' => 'GTM'], ['COUNTRY' => 'GUERNSEY', 'ABBREVIATION' => 'GGY'], ['COUNTRY' => 'GUINEA', 'ABBREVIATION' => 'GIN'], ['COUNTRY' => 'GUINEA-BISSAU', 'ABBREVIATION' => 'GNB'], ['COUNTRY' => 'GUYANA', 'ABBREVIATION' => 'GUY'], ['COUNTRY' => 'HAITI', 'ABBREVIATION' => 'HTI'], ['COUNTRY' => 'HEARDANDMCDONALDISLANDS', 'ABBREVIATION' => 'HMD'], ['COUNTRY' => 'HOLYSEE(VATICANCITYSTATE)', 'ABBREVIATION' => 'VAT'], ['COUNTRY' => 'HONDURAS', 'ABBREVIATION' => 'HND'], ['COUNTRY' => 'HONGKONG', 'ABBREVIATION' => 'HKG'], ['COUNTRY' => 'HUNGARY', 'ABBREVIATION' => 'HUN'], ['COUNTRY' => 'ICELAND', 'ABBREVIATION' => 'ISL'], ['COUNTRY' => 'INDIA', 'ABBREVIATION' => 'IND'], ['COUNTRY' => 'INDONESIA', 'ABBREVIATION' => 'IDN'], ['COUNTRY' => 'IRAN(ISLAMICREPUBLIC)', 'ABBREVIATION' => 'IRN'], ['COUNTRY' => 'IRAQ', 'ABBREVIATION' => 'IRQ'], ['COUNTRY' => 'IRELAND', 'ABBREVIATION' => 'IRL'], ['COUNTRY' => 'ISRAEL', 'ABBREVIATION' => 'ISR'], ['COUNTRY' => 'ITALY', 'ABBREVIATION' => 'ITA'], ['COUNTRY' => 'JAMAICA', 'ABBREVIATION' => 'JAM'], ['COUNTRY' => 'JAPAN', 'ABBREVIATION' => 'JPN'], ['COUNTRY' => 'JERSEY', 'ABBREVIATION' => 'JEY'], ['COUNTRY' => 'JORDAN', 'ABBREVIATION' => 'JOR'], ['COUNTRY' => 'KAZAKHSTAN', 'ABBREVIATION' => 'KAZ'], ['COUNTRY' => 'KENYA', 'ABBREVIATION' => 'KEN'], ['COUNTRY' => 'KIRIBATI', 'ABBREVIATION' => 'KIR'], ['COUNTRY' => 'KOREADEMOCRATICPEOPLE\'SREPUBLIC', 'ABBREVIATION' => 'PRK',], ['COUNTRY' => 'KOREA,REPUBLICOF', 'ABBREVIATION' => 'KOR',], ['COUNTRY' => 'KUWAIT', 'ABBREVIATION' => 'KWT'], ['COUNTRY' => 'KYRGYZSTAN', 'ABBREVIATION' => 'KGZ'], ['COUNTRY' => 'LAOPEOPLE\'SDEMOCRATICREPUBLIC', 'ABBREVIATION' => 'LAO'], ['COUNTRY' => 'LATVIA', 'ABBREVIATION' => 'LVA'], ['COUNTRY' => 'LEBANON', 'ABBREVIATION' => 'LBN'], ['COUNTRY' => 'LESOTHO', 'ABBREVIATION' => 'LSO'], ['COUNTRY' => 'LIBERIA', 'ABBREVIATION' => 'LBR'], ['COUNTRY' => 'LIBYANARABJAMAHIRIYA', 'ABBREVIATION' => 'LBY'], ['COUNTRY' => 'LIECHTENSTEIN', 'ABBREVIATION' => 'LIE'], ['COUNTRY' => 'LITHUANIA', 'ABBREVIATION' => 'LTU'], ['COUNTRY' => 'LUXEMBOURG', 'ABBREVIATION' => 'LUX'], ['COUNTRY' => 'MACAU', 'ABBREVIATION' => 'MAC'], ['COUNTRY' => 'MACEDONIAFORMERYUGOSLAVREPUBLIC', 'ABBREVIATION' => 'MKD',], ['COUNTRY' => 'MADAGASCAR', 'ABBREVIATION' => 'MDG'], ['COUNTRY' => 'MALAWI', 'ABBREVIATION' => 'MWI'], ['COUNTRY' => 'MALAYSIA', 'ABBREVIATION' => 'MYS'], ['COUNTRY' => 'MALDIVES', 'ABBREVIATION' => 'MDV'], ['COUNTRY' => 'MALI', 'ABBREVIATION' => 'MLI'], ['COUNTRY' => 'MALTA', 'ABBREVIATION' => 'MLT'], ['COUNTRY' => 'MAN,ISLEOF', 'ABBREVIATION' => 'IMN',], ['COUNTRY' => 'MARSHALLISLANDS', 'ABBREVIATION' => 'MHL'], ['COUNTRY' => 'MARTINIQUE', 'ABBREVIATION' => 'MTQ'], ['COUNTRY' => 'MAURITANIA', 'ABBREVIATION' => 'MRT'], ['COUNTRY' => 'MAURITIUS', 'ABBREVIATION' => 'MUS'], ['COUNTRY' => 'MAYOTTE', 'ABBREVIATION' => 'MYT'], ['COUNTRY' => 'MEXICO', 'ABBREVIATION' => 'MEX'], ['COUNTRY' => 'MICRONESIA,FEDERATEDSTATES', 'ABBREVIATION' => 'FSM',], ['COUNTRY' => 'MOLDOVAREPUBLIC', 'ABBREVIATION' => 'MDA',], ['COUNTRY' => 'MONACO', 'ABBREVIATION' => 'MCO'], ['COUNTRY' => 'MONGOLIA', 'ABBREVIATION' => 'MNG'], ['COUNTRY' => 'MONTENEGRO', 'ABBREVIATION' => 'MNE'], ['COUNTRY' => 'MONTSERRAT', 'ABBREVIATION' => 'MSR'], ['COUNTRY' => 'MOROCCO', 'ABBREVIATION' => 'MAR'], ['COUNTRY' => 'MOZAMBIQUE', 'ABBREVIATION' => 'MOZ'], ['COUNTRY' => 'MYANMAR', 'ABBREVIATION' => 'MMR'], ['COUNTRY' => 'NAMIBIA', 'ABBREVIATION' => 'NAM'], ['COUNTRY' => 'NAURU', 'ABBREVIATION' => 'NRU'], ['COUNTRY' => 'NEPAL', 'ABBREVIATION' => 'NPL'], ['COUNTRY' => 'NETHERLANDS', 'ABBREVIATION' => 'NLD'], ['COUNTRY' => 'NETHERLANDSANTILLES', 'ABBREVIATION' => 'ANT'], ['COUNTRY' => 'NEWCALEDONIA', 'ABBREVIATION' => 'NCL'], ['COUNTRY' => 'NEWZEALAND', 'ABBREVIATION' => 'NZL'], ['COUNTRY' => 'NICARAGUA', 'ABBREVIATION' => 'NIC'], ['COUNTRY' => 'NIGER', 'ABBREVIATION' => 'NER'], ['COUNTRY' => 'NIGERIA', 'ABBREVIATION' => 'NGA'], ['COUNTRY' => 'NIUE', 'ABBREVIATION' => 'NIU'], ['COUNTRY' => 'NORFOLKISLAND', 'ABBREVIATION' => 'NFK'], ['COUNTRY' => 'NORTHERNMARIANAISLANDS', 'ABBREVIATION' => 'MNP'], ['COUNTRY' => 'NORWAY', 'ABBREVIATION' => 'NOR'], ['COUNTRY' => 'OMAN', 'ABBREVIATION' => 'OMN'], ['COUNTRY' => 'PAKISTAN', 'ABBREVIATION' => 'PAK'], ['COUNTRY' => 'PALAU', 'ABBREVIATION' => 'PLW'], ['COUNTRY' => 'PALESTINIANOCCUPIEDTERRITORY', 'ABBREVIATION' => 'PSE',], ['COUNTRY' => 'PANAMA', 'ABBREVIATION' => 'PAN'], ['COUNTRY' => 'PAPUANEWGUINEA', 'ABBREVIATION' => 'PNG'], ['COUNTRY' => 'PARAGUAY', 'ABBREVIATION' => 'PRY'], ['COUNTRY' => 'PERU', 'ABBREVIATION' => 'PER'], ['COUNTRY' => 'PHILIPPINES', 'ABBREVIATION' => 'PHL'], ['COUNTRY' => 'PITCAIRN', 'ABBREVIATION' => 'PCN'], ['COUNTRY' => 'POLAND', 'ABBREVIATION' => 'POL'], ['COUNTRY' => 'PORTUGAL', 'ABBREVIATION' => 'PRT'], ['COUNTRY' => 'PUERTORICO', 'ABBREVIATION' => 'PRI'], ['COUNTRY' => 'QATAR', 'ABBREVIATION' => 'QAT'], ['COUNTRY' => 'REUNION', 'ABBREVIATION' => 'REU'], ['COUNTRY' => 'ROMANIA', 'ABBREVIATION' => 'ROU'], ['COUNTRY' => 'RUSSIANFEDERATION', 'ABBREVIATION' => 'RUS'], ['COUNTRY' => 'RWANDA', 'ABBREVIATION' => 'RWA'], ['COUNTRY' => 'SAINTHELENA', 'ABBREVIATION' => 'SHN'], ['COUNTRY' => 'SAINTKITTSANDNEVIS', 'ABBREVIATION' => 'KNA'], ['COUNTRY' => 'SAINTLUCIA', 'ABBREVIATION' => 'LCA'], ['COUNTRY' => 'SAINTPIERREANDMIQUELON', 'ABBREVIATION' => 'SPM'], ['COUNTRY' => 'SAINTVINCENT&GRENADINES', 'ABBREVIATION' => 'VCT'], ['COUNTRY' => 'SAMOA', 'ABBREVIATION' => 'WSM'], ['COUNTRY' => 'SANMARINO', 'ABBREVIATION' => 'SMR'], ['COUNTRY' => 'SAOTOMEANDPRINCIPE', 'ABBREVIATION' => 'STP'], ['COUNTRY' => 'SAUDIARABIA', 'ABBREVIATION' => 'SAU'], ['COUNTRY' => 'SENEGAL', 'ABBREVIATION' => 'SEN'], ['COUNTRY' => 'SERBIA', 'ABBREVIATION' => 'SRB'], ['COUNTRY' => 'SEYCHELLES', 'ABBREVIATION' => 'SYC'], ['COUNTRY' => 'SIERRALEONE', 'ABBREVIATION' => 'SLE'], ['COUNTRY' => 'SINGAPORE', 'ABBREVIATION' => 'SGP'], ['COUNTRY' => 'SLOVAKIA(SLOVAKREPUBLIC)', 'ABBREVIATION' => 'SVK'], ['COUNTRY' => 'SLOVENIA', 'ABBREVIATION' => 'SVN'], ['COUNTRY' => 'SOLOMONISLANDS', 'ABBREVIATION' => 'SLB'], ['COUNTRY' => 'SOMALIA', 'ABBREVIATION' => 'SOM'], ['COUNTRY' => 'SOUTHAFRICA', 'ABBREVIATION' => 'ZAF'], ['COUNTRY' => 'SOUTHGEORGIA&SOUTHSANDWICHISLANDS', 'ABBREVIATION' => 'SGS'], ['COUNTRY' => 'SPAIN', 'ABBREVIATION' => 'ESP'], ['COUNTRY' => 'SRILANKA', 'ABBREVIATION' => 'LKA'], ['COUNTRY' => 'SUDAN', 'ABBREVIATION' => 'SDN'], ['COUNTRY' => 'SURINAME', 'ABBREVIATION' => 'SUR'], ['COUNTRY' => 'SVALBARD&JANMAYENISLANDS', 'ABBREVIATION' => 'SJM'], ['COUNTRY' => 'SWAZILAND', 'ABBREVIATION' => 'SWZ'], ['COUNTRY' => 'SWEDEN', 'ABBREVIATION' => 'SWE'], ['COUNTRY' => 'SWITZERLAND', 'ABBREVIATION' => 'CHE'], ['COUNTRY' => 'SYRIA', 'ABBREVIATION' => 'SYR'], ['COUNTRY' => 'TAIWAN', 'ABBREVIATION' => 'TWN'], ['COUNTRY' => 'TAJIKISTAN', 'ABBREVIATION' => 'TJK'], ['COUNTRY' => 'THAILAND', 'ABBREVIATION' => 'THA'], ['COUNTRY' => 'TOGO', 'ABBREVIATION' => 'TGO'], ['COUNTRY' => 'TOKELAU', 'ABBREVIATION' => 'TKL'], ['COUNTRY' => 'TONGA', 'ABBREVIATION' => 'TON'], ['COUNTRY' => 'TRINIDADANDTOBAGO', 'ABBREVIATION' => 'TTO'], ['COUNTRY' => 'TUNISIA', 'ABBREVIATION' => 'TUN'], ['COUNTRY' => 'TURKEY', 'ABBREVIATION' => 'TUR'], ['COUNTRY' => 'TURKMENISTAN', 'ABBREVIATION' => 'TKM'], ['COUNTRY' => 'TURKSANDCAICOSISLANDS', 'ABBREVIATION' => 'TCA'], ['COUNTRY' => 'TUVALU', 'ABBREVIATION' => 'TUV'], ['COUNTRY' => 'UGANDA', 'ABBREVIATION' => 'UGA'], ['COUNTRY' => 'UKRAINE', 'ABBREVIATION' => 'UKR'], ['COUNTRY' => 'UNITEDARABEMIRATES', 'ABBREVIATION' => 'ARE'], ['COUNTRY' => 'UKCITIZEN', 'ABBREVIATION' => 'GBR'], ['COUNTRY' => 'UNITEDSTATESOFAMERICA', 'ABBREVIATION' => 'USA'], ['COUNTRY' => 'URUGUAY', 'ABBREVIATION' => 'URY'], ['COUNTRY' => 'UZBEKISTAN', 'ABBREVIATION' => 'UZB'], ['COUNTRY' => 'VANUATU', 'ABBREVIATION' => 'VUT'], ['COUNTRY' => 'VENEZUELA', 'ABBREVIATION' => 'VEN'], ['COUNTRY' => 'VIETNAM', 'ABBREVIATION' => 'VNM'], ['COUNTRY' => 'VIRGINISLANDS(BRITISH)', 'ABBREVIATION' => 'VGB'], ['COUNTRY' => 'VIRGINISLANDS(U.S.)', 'ABBREVIATION' => 'VIR'], ['COUNTRY' => 'WALLISANDFUTUNAISLANDS', 'ABBREVIATION' => 'WLF'], ['COUNTRY' => 'WESTERNSAHARA', 'ABBREVIATION' => 'ESH'], ['COUNTRY' => 'YEMEN', 'ABBREVIATION' => 'YEM'], ['COUNTRY' => 'YUGOSLAVIA', 'ABBREVIATION' => 'YUG'], ['COUNTRY' => 'ZAMBIA', 'ABBREVIATION' => 'ZMB'], ['COUNTRY' => 'ZIMBABWE', 'ABBREVIATION' => 'ZWE'], ['COUNTRY' => 'ALANDISLANDS', 'ABBREVIATION' => 'ALA'], ['COUNTRY' => 'BONAIRE,SINTEUSTATIUSANDSABA', 'ABBREVIATION' => 'BES',], ['COUNTRY' => 'SAINTBARTHELEMY', 'ABBREVIATION' => 'BLM'], ['COUNTRY' => 'CURACAO', 'ABBREVIATION' => 'CUW'], ['COUNTRY' => 'SAINTMARTIN', 'ABBREVIATION' => 'MAF'], ['COUNTRY' => 'SOUTHSUDAN', 'ABBREVIATION' => 'SSD'], ['COUNTRY' => 'SINTMAARTEN(DUTCHPART)', 'ABBREVIATION' => 'SXM'], ['COUNTRY' => 'UNITEDSTATESMINOROUTLYINGISLANDS', 'ABBREVIATION' => 'UMI'], ['COUNTRY' => 'UK-DEPENDENTTERRITORIESCITIZEN', 'ABBREVIATION' => 'GBD'], ['COUNTRY' => 'UK-NATIONAL(OVERSEAS)', 'ABBREVIATION' => 'GBN'], ['COUNTRY' => 'UK-OVERSEASCITIZEN', 'ABBREVIATION' => 'GBO'], ['COUNTRY' => 'UNITEDNATIONSORGANIZATION', 'ABBREVIATION' => 'UNO'], ['COUNTRY' => 'UNSPECIALIZEDAGENCYOFFICIAL', 'ABBREVIATION' => 'UNA'], ['COUNTRY' => 'STATELESS', 'ABBREVIATION' => 'XXA'], ['COUNTRY' => 'REFUGEE', 'ABBREVIATION' => 'XXB'], ['COUNTRY' => 'REFUGEE(NON-CONVENTION)', 'ABBREVIATION' => 'XXC'], ['COUNTRY' => 'UNSPECIFIED/UNKNOWN', 'ABBREVIATION' => 'XXX'], ['COUNTRY' => 'UK-PROTECTEDPERSON', 'ABBREVIATION' => 'GBP'], ['COUNTRY' => 'UK-SUBJECT', 'ABBREVIATION' => 'GBS'], ['COUNTRY' => 'AFRICANDEVELOPMENTBANK', 'ABBREVIATION' => 'XBA'], ['COUNTRY' => 'AFRICANEXPORT–IMPORTBANK', 'ABBREVIATION' => 'XIM'], ['COUNTRY' => 'CARIBBEANCOMMUNITYORONEOFITSEMISSARIES', 'ABBREVIATION' => 'XCC'], ['COUNTRY' => 'COMMONMARKETFOREASTERNANDSOUTHERNAFRICA', 'ABBREVIATION' => 'XCO'], ['COUNTRY' => 'ECONOMICCOMMUNITYOFWESTAFRICANSTATES', 'ABBREVIATION' => 'XEC'], ['COUNTRY' => 'INTERNATIONALCRIMINALPOLICEORGANIZATION', 'ABBREVIATION' => 'XPO'], ['COUNTRY' => 'SOVEREIGNMILITARYORDEROFMALTA', 'ABBREVIATION' => 'XOM']
        ];
    }
}
