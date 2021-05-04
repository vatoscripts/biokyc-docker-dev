<?php

namespace App\Http\Controllers\Report;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Input;
use App\Http\Controllers\GuzzleController as GuzzleController;
use Session;

class KYAReportController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
		$this->middleware(['role:ROLE_ADMIN,ROLE_BACK_OFFICE,ROLE_FORENSIC']);
    }

    public function viewAll() {
        $url = 'Agent';

        $data = $this->getRequest($url);

        return view('reports.kya.agents.index')->with('agents', $data);
    }

    public function index() {
        return view('reports.kya.agents.index');
    }

    public function fetchAgentsByLocation(Request $request) {
        // $messages = [
        //     'agentZone.required' => 'Please specify agent\'s zone !',
        // ];

        // $this->validate($request, [
        //     'agentZone' => 'required',
        // ], $messages);

        // $id = $request->input('agentZone');
        //

        $body = [
            'TerritoryID' => $request->input('agentTerritory')?(int) $request->input('agentTerritory') : null,
            'RegionID' => $request->input('agentRegion')?(int) $request->input('agentRegion') : null,
            'ZoneID' => $request->input('agentZone')?(int) $request->input('agentZone') : null,
        ];

        $url = 'FilterAgentByLocation';

        $data = $this->postRequest($url, $body);

        return response()->json([
            'data', $data
        ],200);

    }

    public function getZones()
    {
        $url = '/zone/';
        $zone = $this->getRequest($url);

        return $zone;
    }

    public function showBlankAgentLocation() {
        return view('reports.kya.agents.zones');
    }

    public function viewStaffOnboardedIMS()
    {
        $url = 'GetIMSOnboardedStaff';

        $data = $this->getRequest($url);

        return view('reports.kya.agentstaff.verifiedIMS')->with('staff', $data);
    }

    public function viewStaffByLocation()
    {
        return view('reports.kya.agentstaff.location');
    }

    public function getStaffByLocation(Request $request)
    {
        $body = [
            'ImsRegion' => (int) $request->input('region'),
            'District' => (int) $request->input('district'),
            'ImsWard' => (int) $request->input('ward'),
            'ImsVillage' => (int) $request->input('village'),
        ];

        $url = 'FilterAgentStaffByLocation';

        $data = $this->postRequest($url, $body);

        return response()->json([
            'data' => $data
        ], 200);
    }

    public function viewStaffByregistrations()
    {
        return view('reports.kya.agentstaff.registrations');
    }

    public function viewStaffByAgentID()
    {
        return view('reports.kya.agentstaff.agent');
    }

    public function staffByAgent(Request $request)
    {
        $ID = (int) $request->get('agentFrom');

        $data = $this->getStaffByAgent($ID);

        return view('reports.kya.agentstaff.agent')->with('staff', $data);
    }

    public function getStaffByAgent($Id)
    {
        $url = 'AgentStaffList/' . $Id;

        $data = $this->getRequest($url);

        return $data;
    }

}
