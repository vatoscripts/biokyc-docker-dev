<?php

namespace App\Http\Controllers\Home;

use Illuminate\Http\Request;
use Session;
use App\Jenga;
use App\Http\Controllers\GuzzleController as GuzzleController;
use PhpParser\Node\Stmt\TryCatch;
use League\Flysystem\Exception;
use App\Http\Requests\KycRequest;
use GuzzleHttp\Exception\GuzzleException;
use View;
use Illuminate\Support\Facades\Log;


class DashboardController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
    }

    public function index2()
    {
        //Log::channel('kyEmergency')->emergency('A transaction has been made!', ['user' => $this->user, 'previous_page' => 'www.google.com']);
        return view('dashboard.index2');
    }

    public function index()
    {
		//Log::channel('kyEmergency')->emergency('A transaction has been made!', ['user' => $this->user, 'previous_page' => 'www.google.com']);
        return view('dashboard.index')->with(
            [
                'total' => $this->getTotalRegs(),
                'recents' => $this->getRecentRegs(),
                'regSummary' => $this->getRegSummary(),
                'user' => $this->user
            ]
        );
    }

    private function getTotalRegs()
    {
        $url = 'RegCount/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return $data;
    }

    private function getRecentRegs()
    {
        $url = 'RecentRegActivity/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return $data;

    }

    private function getRegSummary()
    {
        $url = 'RegistrationSummary/' . $this->user['UserID'];

        $data = $this->getRequest($url);

        return $data;
    }

    public function getCustDetails($id)
    {
        $url = 'SingleCustomer/' . $id;

        $data = $this->getRequest($url);

        return view('dashboard.customer-details')->with('data', $data);
    }

    public function showMyArray()
    {
        $myJSON = '[{"attributeName":"MSISDN_1","attributeValue":"255753739657"},{"attributeName":"TCRA_STATUS_1","attributeValue":"PRIMARY"},{"attributeName":"REGISTRATION_TYPE_1","attributeValue":"VISI"},{"attributeName":"MSISDN_2","attributeValue":"255766038472"},{"attributeName":"TCRA_STATUS_2","attributeValue":"SECONDARY"},{"attributeName":"REGISTRATION_TYPE_2","attributeValue":"VISI"},{"attributeName":"MSISDN_3","attributeValue":"255769177526"},{"attributeName":"TCRA_STATUS_3","attributeValue":"PRIMARY"},{"attributeName":"REGISTRATION_TYPE_3","attributeValue":"VISI"},{"attributeName":"MSISDN_4","attributeValue":"255768724611"},{"attributeName":"TCRA_STATUS_4","attributeValue":"SECONDARY"},{"attributeName":"REGISTRATION_TYPE_4","attributeValue":"VISI"},{"attributeName":"MSISDN_5","attributeValue":"255743853016"},{"attributeName":"TCRA_STATUS_5","attributeValue":"PRIMARY"},{"attributeName":"REGISTRATION_TYPE_5","attributeValue":"VISI"},{"attributeName":"MSISDN_6","attributeValue":"255753082591"},{"attributeName":"TCRA_STATUS_6","attributeValue":"PRIMARY"},{"attributeName":"REGISTRATION_TYPE_6","attributeValue":"VISI"},{"attributeName":"MSISDN_7","attributeValue":"255762452333"},{"attributeName":"TCRA_STATUS_7","attributeValue":"SECONDARY"},{"attributeName":"REGISTRATION_TYPE_7","attributeValue":"VISI"},{"attributeName":"MSISDN_8","attributeValue":"255757769212"},{"attributeName":"TCRA_STATUS_8","attributeValue":"PRIMARY"},{"attributeName":"REGISTRATION_TYPE_8","attributeValue":"VISI"}]';

        $myArray = json_decode($myJSON);

        $finalArray = [];

        foreach($myArray as $key => $value) {
            foreach($value as $i) {
                array_push($finalArray, $i);
            }
        }

        foreach($finalArray as $j => $k) {
            if($j % 2 == 0) {
                unset($finalArray[$j]);
            }
        }

        dd(array_chunk($finalArray,3));

        return view('test');
    }
}
