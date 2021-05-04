<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Http\Controllers\GuzzleController as GuzzleController;
use Session;
use Illuminate\Support\Facades\Input;

class KYAReportsController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
		$this->middleware(['role:ROLE_ADMIN,ROLE_SUPPORT_OFFICER']);
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


}
