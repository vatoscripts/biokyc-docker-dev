<?php

namespace App\Http\Controllers\KYA;

use Illuminate\Http\Request;
use Session;
use App\Http\Controllers\GuzzleController as GuzzleController;
use PhpParser\Node\Stmt\TryCatch;
use League\Flysystem\Exception;
use App\Http\Requests\KycRequest;
use GuzzleHttp\Exception\GuzzleException;
use function GuzzleHttp\json_encode;
use App\Http\Requests\AgentOnboardRequest;
use Illuminate\Support\Facades\Log;

class RecruiterController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_AGENT,ROLE_ADMIN']);
    }

    public function index()
    {
        $url = 'GetRecruiters/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return view('recruiters.index')->with('recruiters', $data);
    }

    public function createStaffRecruiter(Request $request)
    {
        $messages = [
            'msisdn.required' => 'We need to know Recruiter\'s phone number !',
            'NIN.required' => 'We need to know Recruiter\'s NIDA ID number !',
            'msisdn.regex' => 'Wrong Recruiter\'s phone number format !',
            'NIN.numeric' => 'Wrong NIDA ID number format !',
            'NIN.digits' => 'Wrong Wrong NIDA ID number length !',
            'shopName.required' => 'We need to know Recruiter\'s Shop Name !',
            'domain-username.required_if' => 'We need to know Recruiter\'s Domain Username !',
            'fingerCode.required' => 'Please Select Recruiter\'s finger index !',
            'fingerData.required' => 'Please Capture Recruiter\'s finger print !',
        ];

        $this->validate($request, [
            'msisdn' => 'required|regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})/',
            'NIN' => 'required|numeric|digits:20',
            'shopName' =>'required',
            'domain-username' =>'required_if:domainYN,Y',
            'fingerCode' => 'required',
            'fingerData' => 'required',

        ], $messages);

        $body = [
            'NIN' => $request->input('NIN'),
            'FingerCode' => $request->get('fingerCode'),
            'FingerData' => $request->get('fingerData'),
            'MobilePhone' => $request->input('msisdn'),
            'UserID' => $this->user['UserID'],
            'ShopID' => (int)$request->get('shopName'),
            'DomainYN' => $request->get('domain-username')==null?'N':'Y',
            'UserName' => $request->get('domain-username')==null?"":$request->get('domain-username'),
        ];

        $url = 'CreateAgentStaffRecruiter';

        $data = $this->postRequest($url, $body);

        Log::channel('Recruiter')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] === 0) {
            return response()
                ->json([
                    'message' => 'Agent Recruiter Successful Onboarding !',
                    'status' => $data['ID']
                ], 200);
        }

        elseif ($data['ID'] == 01) {
            return response()
                ->json([
                    'message' => 'Customer Biometric verification failed 01 !',
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 132) {
            return response()
                ->json([
                    'message' => 'Customer NIN not found !',
                    'status' => $data['ErrorCode']
                ], 400);
        } elseif ($data['ID'] == 141) {
            return response()
                ->json([
                    'message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !',
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == '02') {
            return response()
                ->json([
                    'message' => 'User already exists in the system !',
                    'status' => $data['ID']
                ], 400);
        } else {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        }
    }

    public function viewRecruiter($id)
    {
        $url = 'GetSingleRecruiter/' . $id;

        $data = $this->getRequest($url);

        if ($data['ProfileID'] === 0) {
            return redirect()->route('recruiter.list')->with('warning', 'Sorry ! Recruiter could not be found');
        }


        return view('recruiters.view')->with('agent', $data);
    }

    public function blockRecruiter($recruiterID)
    {
        $url = '/BlockAgentStaffRecruiter';

        $body = [
            'profileID' => (int) $recruiterID
        ];

        $data = $this->postRequest($url, $body);

        if ($data['ID'] <> 1) {
            return back()->with('danger', 'Something went wrong. Try again!');
        }

        return back()->with('success', 'Recruiter deactivated successful. Thank you!');
    }

    public function unblockRecruiter($recruiterID)
    {
        $url = '/ActivateAgentStaffRecruiter';

        $body = [
            'profileID' => (int) $recruiterID
        ];

        $data = $this->postRequest($url, $body);

        if ($data['ID'] <> 1) {
            return back()->with('danger', 'Something went wrong. Try again!');
        }

        return back()->with('success', 'Recruiter activated successful. Thank you!');
    }
}
