<?php

namespace App\Http\Controllers\Support;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Controllers\GuzzleController as GuzzleController;


class KYCSupportController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN,ROLE_SUPPORT_OFFICER,ROLE_BACK_OFFICE,ROLE_FORENSIC,ROLE_CHECKER']);
        $this->middleware(['role:ROLE_CHECKER,ROLE_ADMIN'])->only(['allVisitorAlternative', 'singleVisitorAlternative']);
    }

    public function viewCustomerRegDetails()
    {
        return view('support.kyc.msisdn-reg-details');
    }

    public function getCustomerRegDetails(Request $request)
    {
        $messages = [
            'msisdn.required' => 'Please Enter Customer MSISDN',
            'msisdn.regex' => 'Please Enter valid Customer MSISDN e.g 07547000000',
            'startDate.required' => 'Please Enter End Date !',
            'endDate.required' => 'Please Enter End Date !',
            'reportType.required' => 'Please Choose Type !',
        ];

        $this->validate($request, [
            'msisdn' => 'required|regex:/\+?(0)-?([0-9]{3})-?([0-9]{6})$/',
            'startDate' => 'required',
            'endDate' => 'required',
            'reportType' => 'required',
        ], $messages);

        $body = [
            'Msisdn' => $request->msisdn,
            'startDate' => $request->startDate,
            'endDate' => $request->endDate,
            'ReportType' => (int) $request->reportType
        ];

        $url = 'GetRegByMsisdn';

        $data = $this->postRequest($url, $body);

        return response()->json($data, 200);
    }

    public function regDetailsPerID()
    {
        return view('support.kyc.id-reg-details');
    }

    public function allVisitorAlternative()
    {
        return view('support.kyc.alt-visitor-primary');
    }

    public function singleVisitorAlternative()
    {
        return view('support.kyc.single-alt-visitor-primary');
    }
}
