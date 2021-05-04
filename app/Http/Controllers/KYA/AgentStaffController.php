<?php

namespace App\Http\Controllers\KYA;

use Illuminate\Http\Request;
use App\Http\Controllers\GuzzleController as GuzzleController;
use PhpParser\Node\Stmt\TryCatch;
use League\Flysystem\Exception;
use App\Http\Requests\KycRequest;
use App\Http\Requests\AgentOnboardRequest;
use View;
use Validator;
use Session;
use Illuminate\Support\Facades\Log;

use function GuzzleHttp\json_encode;

class AgentStaffController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_STAFF_RECRUITER,ROLE_AGENT'])->except(['getRegionId', 'getDistrict', 'getWard', 'getVillage']);
    }

    public function index()
    {
        $url = 'AgentStaffList/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return view('agentstaff.index')->with(['agentstaff' => $data, 'NONIDA', 'user' => $this->user['Role']]);
    }

    public function getAgentStaffDetails($id)
    {
        $url = 'GetAgentStaffByStaffID/' . $id;

        Session::flash('AgentID', $id);

        $data = $this->getRequest($url);

        if ($data['AgentStaffID'] === 0) {
            return redirect()->route('agentstaff')->with('warning', 'Sorry ! AgentStaff could not be found');
        }

        return view('agentstaff.show')->with(['staff' => $data, 'id' => $id]);
    }

    public function getRegionId($Id)
    {
        $url = 'RegionIDByRegionName?ImsRegionName=' . $Id;
        $region = $this->getRequest($url);

        return $region;
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

    public function postAgentStaffAddress(Request $request)
    {
        $input =  $request->getContent();

        $Ret = json_encode($input);
        $url = "AgentAddress?value=" . $Ret;
        $territory = $this->getRequest($url);

        return $territory;
    }

    public function blockAgentStaff(Request $request)
    {
        $messages = [
            'blockReason.required' => 'Please specify your reason for blocking this staff !',
            'block-reason-text.required' => 'We need to know your reason for blocking this staff !',
        ];

        $this->validate($request, [
            'blockReason' => 'required',
        ], $messages);

        $reason = $request->input('blockReason');

        if ($request->input('blockReason') == 'Others –(Specify)') {
            $this->validate($request, [
                'block-reason-text' => 'required',
            ], $messages);
            $reason = $request->input('block-reason-text');
        }

        $url = 'BlockAgentStaff';

        $body = [
            'AgentStaffID' => (int) $request->input('staffId'),
            'DeactivateReason' => $reason,
            'DeactivatedBy' => $this->user['UserID']
        ];

        $data = $this->postRequest($url, $body);

        if ($data['ID'] <> 0 && $data['Description'] !== 'OK') {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] === 0 && $data['Description'] === 'OK') {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 200);
        }
    }

    public function unBlockAgentStaff(Request $request)
    {
        $messages = [
            'unblockReason.required' => 'Please specify your reason for activating this staff!',
            'Unblock-Staff-file.required' => 'Please attach approval doc',
        ];

        $this->validate($request, [
            'unblockReason' => 'required',
        ], $messages);

        $reason = $request->input('unblockReason');

        if ($request->hasFile('Unblock-Staff-file')) {
            $this->validate($request, [
                'Unblock-Staff-file' => 'required|file',
            ], $messages);
        }

        // if ($request->input('unblockReason') == 'approved') { }

        // if ($reason == 'approved') {
        //     //dd($request->file('Unblock-Staff-file'));
        //     $unblockFile = file_get_contents($request->file('Unblock-Staff-file'));
        //     $unblockFilebase64 = base64_encode($unblockFile);
        //     $reason = 'Approved to be Unlocked – See attached reason/ approval document';
        // }

        $url = 'ActivateAgentStaff';

        $body = [
            'AgentStaffID' => (int) $request->input('staffId'),
            'ActivationReason' => $reason,
            'ActivatedBy' => $this->user['UserID'],
            'ActivationDoc' => 'none',
        ];

        $data = $this->postRequest($url, $body);

        if ($data['ID'] <> 0 && $data['Description'] !== 'OK') {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] === 0 && $data['Description'] === 'OK') {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 200);
        }
    }

    public function createAgentStaffDB(Request $request)
    {
        $messages = [
            'mobile-phone.required' => 'Please Input Agent Staff\'s phone number!',
            'NIN.required' => 'Please Input Agent Staff\'s NIDA ID number!',

            'mobile-phone.regex' => 'Wrong Agent Staff\'s phone number format !',
            'NIN.numeric' => 'Wrong NIDA ID number format !',
            'NIN.digits' => 'Wrong Wrong NIDA ID number length !',
            'shopName.required' => 'Please Input Agent Staff\'s Shop Name !',
            'fingerCode.required' => 'Please Select Agent Staff\'s finger index !',
            'fingerData.required' => 'Please Capture Agent Staff\'s finger print !',
        ];

        $this->validate($request, [
            'mobile-phone' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/',
            'NIN' => 'required|numeric|digits:20',
            'shopName' => 'required',
            'domain-username' => 'required_if:domainYN,Y',
            'fingerCode' => 'required',
            'fingerData' => 'required',
        ], $messages);

        $body = [
            'NIN' => $request->input('NIN'),
            'FingerCode' => $request->get('fingerCode'),
            'FingerData' => $request->get('fingerData'),
            'MobilePhone' => $request->input('mobile-phone'),
            'UserID' => $this->user['UserID'],
            'ShopID' => (int) $request->get('shopName'),
            'DomainYN' => 'N',
            'UserName' => '',
        ];

        $url = 'CreateStaffAgent';

        $data = $this->postRequest($url, $body);

        Log::channel('Registral')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] === 0) {
            return response()
                ->json([
                    'message' => 'Succesful Agent Staff Onboarding !',
                    'status' => $data['ID']
                ], 200);
        } elseif ($data['ID'] == 01) {
            return response()
                ->json([
                    'message' => 'Customer Biometric verification failed',
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 132) {

            return response()
                ->json([
                    'message' => 'Customer NIN not found',
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 141) {
            return response()
                ->json([
                    'message' => 'Customer Biometric Fingerprint Verification Failed 141. Use another finger !',
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 2) {
            return response()
                ->json([
                    'message' => 'User already exists in the system !',
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 3) {
            return response()
                ->json([
                    'message' => 'User with same NIN already exists in the system !',
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

    public function verifyAgentIMS1(Request $request)
    {
        $validatedData = $request->validate([
            'DeviceID' => 'required|max:25',
        ]);

        $agentID = (int) $request->get('agentID');

        $body = [
            'AgentStaffID' => $agentID,
            //'AgentStaffID' => 1,
            'famocoID' => $request->get('DeviceID'),
            'UserID' => $this->user['UserID'],
        ];

        $url = 'FullVerifyAgent';

        $data = $this->postRequest($url, $body);


        if ($data['status'] === "success") {
            $regionChafu =  $data['results']['device']['region'];
            $regionSafi = trim(preg_replace('/\t+/', '', $regionChafu));
            $region = $this->getRegionId($regionSafi);
            return $this->getonboardAgentIMS($region[0]['ID'], $request->get('DeviceID'), $agentID);
        } elseif ($data['code'] === null && $data['message']) {
            return back()->withErrors($data['message'])->withInput();
        }

        return back()->withErrors($data['message'])->withInput();
    }

    public function onboardAgentIMS1(Request $request)
    {
        $isShared = ($request->input('isShared')) ? 1 : 0;

        $body = [
            'RegionID' => $request->input('regionID'),
            'DistrictID' => $request->input('district'),
            'WardID' => $request->input('ward'),
            'VillageID' => $request->input('village'),
            'AgentStaffID' => $request->input('staffID'),
            'UserID' => $this->user['UserID'],
            'isShared' => $isShared,
            'DeviceID' => $request->get('deviceID')
        ];

        $url = 'OnboardAgentStaff';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] === 0) {
            return redirect()->route('agentstaff.details', $request->input('staffID'))->with('success', 'Successful Staff Onboarding ');
        } else {
            return redirect()->route('agentstaff.details', $request->input('staffID'))->with('danger', $data['Description']);
        }

        return redirect()->route('agentstaff.details', $request->input('staffID'))->with('danger', $data['Description']);
    }

    public function getverifyAgentIMS($Id)
    {
        return view('agentstaff.staff-verify')->with('agentID', $Id);
    }

    public function getonboardAgentIMS($region, $deviceID, $staffID)
    {
        return view('agentstaff.staff-onboard')->with([
            'region' => $region,
            'deviceID' => $deviceID,
            'staffID' => $staffID,
        ]);
    }

    public function clearIMSDevice(Request $request)
    {

        $body = [
            'AgentStaffID' => (int) $request->agentStaffID,
            'userID' => $this->user['UserID'],
        ];

        $url = 'ReleaseAgentStaff';

        $data = $this->postRequest($url, $body);


        if ($data['ID'] === 1) {
            return back()->with('success', 'Successful device is now removed from this staff agent!');
        } else {
            return back()->withErrors('Sorry, operation failed, try again later!');
        }

        return back()->withErrors('Oops! Could not remove device from this staff agent. Please Try again!');
    }

    public function showstaffMigrate()
    {
        return view('agentstaff.agent-staff-migration');
    }

    public function staffMigrate(Request $request)
    {
        $messages = [
            'agentFrom.required' => 'We need to know donor Agent !',
            'agentTo.required' => 'We need to know receiving Agent !',
            'staff-migration-reason.required' => 'We need to know your reason for this migration !',
        ];

        $this->validate($request, [
            'agentFrom' => 'required',
            'agentTo' => 'required',
            'staff-migration-reason' => 'required',
        ], $messages);

        $body = [
            'MigratedBy' => $this->user['UserID'],
            'AgentStaffID' => (int) $request->get('staff')[0],
            'PreviousAgent' => (int) $request->get('agentFrom'),
            'NewAgent' => (int) $request->get('agentTo'),
            'MigrationReason' => $request->get('staff-migration-reason'),
        ];

        $url = 'AgentStaffMigration';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] === 1) {
            return back()->with('success', 'Succefully staff migration !');
        } elseif ($data['ID'] <> 1) {
            return back()->withErrors($data['Description'])->withInput();
        }

        return back()->withErrors('Something Went Wrong, Please try again !')->withInput();
    }

    public function getRegions()
    {
        $url = 'Imsregions';

        return $this->getRequest($url);
    }

    public function releaseIMSDevice(Request $request)
    {

        $body = [
            'AgentStaffID' => $request->agentStaffID,
            'userID' => $this->user['UserID'],
        ];

        $url = 'ReleaseAgentStaff';

        //$data = $this->postRequest($url, $body);

        dd($body);

        // if ($data['ID'] === 0) {
        //     return redirect()->route('agentstaff.details', $request->input('staffID'))->with('success', 'Successful Staff Onboarding ');
        // } else {
        //     return back()->withErrors('Oops! Could not complete Onboarding. Please Try again!');
        // }

        // return back()->withErrors('Oops! Could not complete Onboarding. Please Try again!');
    }

    public function getRecruiterByUserID()
    {
        $url = 'RecruiterByUserId/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return $data;
    }
}
