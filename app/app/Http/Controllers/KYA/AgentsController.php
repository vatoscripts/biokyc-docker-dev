<?php

namespace App\Http\Controllers\KYA;

use Illuminate\Http\Request;
use Session;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\AgentRequest;
use Illuminate\Support\Facades\Log;

class AgentsController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN,ROLE_BACK_OFFICE'])->except(['getAgentByUser','getAgentShops']);
    }

    public function index()
    {
        $data = $this->getAgentList();

        return view('agents.index')->with(['agents' => $data, 'NONIDA']);
    }

    public function getAgentList()
    {
        $url = 'Agent';

        $data = $this->getRequest($url);

        return $data;
    }

    public function getAgentDetails($id)
    {
        $url = 'Agent/' . $id;

        $data = $this->getRequest($url);

        return view('agents.agent-details')->with(['agent' => $data, 'id' => $id]);
    }

    public function getZones()
    {
        $url = 'zone/';
        $zone = $this->getRequest($url);

        return $zone;
    }

    public function getRegions($Id)
    {
        $url = 'region/' . $Id;
        $region = $this->getRequest($url);

        return $region;
    }

    public function getTerritory($Id)
    {
        $url = 'Territory/' . $Id;
        $territory = $this->getRequest($url);

        return $territory;
    }

    public function postAgentAddress(Request $request)
    {
        $input =  $request->getContent();

        $Ret = json_encode($input);

        $url = "AgentAddress?value=" . $Ret;
        $territory = $this->getRequest($url);

        return $territory;
    }

    public function createAgentQueryNIDA(AgentRequest $request)
    {
        $body = [
            'NIN' => $request->input('NIN'),
            'FingerCode' => $request->get('fingerCode'),
            'FingerData' => $request->get('fingerData'),
            'UserID' => $this->user['UserID'],
        ];

        $url = 'NIDA';

        $data = $this->postRequest($url, $body);

        $data2 = $data;

        unset( $body['FingerData']);
        unset( $data2['PHOTO']);
        unset( $data2['SIGNATURE']);

        Log::channel('Agent')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data2]);

        if ($data['ErrorCode'] == 0) {
            session::put('NIDAdata', $data);
            return response()
                ->json([
                    'message' => $data['ErrorMessage'],
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
        } else {
            return response()
                ->json([
                    'message' => $data['ErrorMessage'],
                    'status' => $data['ErrorCode']
                ], 400);
        }
    }

    public function createAgentDB(AgentRequest $request)
    {
        $NIDAdata = $request->session()->get('NIDAdata');

        if ($request->file('TIN-file'))
        {
            $TINfile = file_get_contents($request->file('TIN-file'));
            $TINfilebase64 = base64_encode($TINfile);
            if (!$request->filled('TIN'))
            {
                return response()->json([
                    'message' => 'TIN Number Can not be Empty !'
                ], 400 );
            }

             if(!$request->file('business-licence-file'))
            {
                return response()->json([
                    'message' => ' Please Upload Business Licence File !'
                ], 400 );
            }

        }
        else
        {
            $TINfilebase64 = null;
        }

        if ($request->file('business-licence-file'))
        {
            $BusinessFile = file_get_contents($request->file('business-licence-file'));
            $BusinessFilebase64 = base64_encode($BusinessFile);

            if (!$request->filled('business-licence'))
            {
                return response()->json([
                    'message' => 'Business Licence Number Can not be Empty !'
                ], 400 );
            }

            if(!$request->file('TIN-file'))
            {
                return response()->json([
                    'message' => ' Please Upload TIN File !'
                ], 400 );
            }
        }
        else
        {
            $BusinessFilebase64 = null;
        }

        if($request->filled('TIN'))
        {
            if(!$request->file('TIN-file'))
            {
                return response()->json([
                    'message' => 'Please Upload TIN File !'
                ], 400 );
            }
        }

        if($request->filled('business-licence'))
        {
            if(!$request->file('business-licence-file'))
            {
                return response()->json([
                    'message' => 'Please Upload Business Licence File !'
                ], 400 );
            }
        }

        $body = [
            'BusinessName' => $request->input('business-name'),
            'TIN' => $request->input('TIN'),
            'BusinessLicenceNo' => $request->input('business-licence'),
            'UserID' => $this->user['UserID'],
            'Address' => $request->input('business-location'),
            'NIN' => $NIDAdata['NIN'],
            'TerritoryID' => 0,
            'ActiveYN' => 'Y',
            'DeactivateReason' => '',
            'AgentCode' => $request->input('mobile-phone'),
            'AgentID' => 0,
            'TinImage' => $TINfilebase64,
            'BusinessImage' => $BusinessFilebase64,
            'MobilePhone' => $request->input('mobile-phone'),
            'FirstName' => $NIDAdata['FIRSTNAME'],
            'MiddleName' => $NIDAdata['MIDDLENAME'],
            'Surname' => $NIDAdata['SURNAME'],
            'Gender' => $NIDAdata['SEX'],
            'TelPhone' => $request->input('business-phone'),
            'DOB' => $NIDAdata['DATEOFBIRTH'],
            'Photo' => $NIDAdata['PHOTO'],
            'email' => $request->input('email'),
            'channelType' => $request->input('agent-category'),
            'IsAD' => "N",
            'username' => "",
            'NidaTransactionID' => $NIDAdata['ID']
        ];

        $url = 'Agent';

        unset( $body['Fingerprints']);

        $data = $this->postRequest($url, $body);

        Log::channel('Agent')->emergency(['user' => $this->user['UserName'], 'Request' => $body, 'Response' => $data]);

        if ($data['ID'] !== 0 || $data['Description'] !== null) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] === 0 && $data['Description'] == null) {
            $request->session()->forget('NIDAdata');
            return response()
                ->json([
                    'message' => "Agent Successfully Created. Thank you !",
                    'status' => $data['ID']
                ], 200);
        }

        return response()
            ->json([
                'message' => 'Sorry, Something went wrong',
                'status' => -1
            ], 400);
    }

    public function blockAgent($Id)
    {
        $url = 'BlockAgent';

        $body = [
            'AgentID' => $Id,
            'DeactivateReason' => 'Fraud',
        ];

        $data = $this->postRequest($url, $body);

        return back()->with('success', 'Agent deactivated successful. Thank you!');
    }

    public function unBlockAgent($Id)
    {
        $url = 'ActivateAgent';

        $body = [
            'AgentID' => $Id,
        ];

        $data = $this->postRequest($url, $body);

        return back()->with('success', 'Agent Activated successfully. Thank you!');
    }

    public function getAgentCategory()
    {
        $url = 'AgentCategories';
        return $this->getRequest($url);
    }

    public function getAgentShops($id)
    {
        $urlShop = 'AgentShopList/' . $id;

        $shops = $this->getRequest($urlShop);

        return $shops;
    }

    public function showAgentShops($id)
    {
        $urlShop = 'AgentShopList/' . $id;

        $shops = $this->getRequest($urlShop);

        $urlAgent = 'Agent/' . $id;

        $agent = $this->getRequest($urlAgent);

        return view('agents.shops-list')->with(['shops'=> $shops, 'agent' => $agent]);
    }

    public function AgentShopSave(Request $request) {

        $body = [
            'AgentID' => (int)$request->agentID,
            'ShopID' => 0,
            'ShopName' => $request->shopName,
            'ShopCode' =>  $request->shopCode,
            'TerritoryID' =>  (int)$request->territory,
        ];

        $url = 'RegisterAgentShop';

        $data = $this->postRequest($url, $body);

        if($data['ID'] == 0) {
            return redirect()->route('agents')->with('success', 'Shop Added successful. Thank you!');
        }

        return back()->withErrors(['message' => 'An Error Occured : ' . $data['Description']]);
    }

    public function showAgentProfile()
    {
        $urlAgent = 'Agentbyuser/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return view('agents.agent-details')->with(['agent' => $data, 'id' => $id]);
    }

    public function getAgentByUser()
    {
        $url = 'Agentbyuser/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return $data;
    }

    public function editShop($agentId, $shopId)
    {
        $urlShop = 'AgentShopList/' . $agentId;

        $shops = $this->getRequest($urlShop);

        $urlAgent = 'Agent/' . $agentId;

        foreach($shops as $shop)
        {
            if($shop['ShopID'] == $shopId)
            {
                $thisShop =  $shop;
            }
        }

        $agent = $this->getRequest($urlAgent);

        return view('agents.shop-edit-modal')->with(['shop'=> $thisShop, 'agent' => $agent]);
    }
}
