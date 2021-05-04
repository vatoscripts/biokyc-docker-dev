<?php

namespace App\Http\Controllers\Report;

use Illuminate\Http\Request;
use App\Http\Requests\KYCReportsRequest;
use Illuminate\Support\Facades\Log;
use Maatwebsite\Excel\Facades\Excel;
use App\Exports\RegJourney;
use App\Exports\SIMSwap;
use App\Http\Controllers\GuzzleController as GuzzleController;

class KYCReportController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN,ROLE_BACK_OFFICE,ROLE_FORENSIC']);
    }

    public function viewRegJourney()
    {
        return view('reports.kyc.reg-journey');
    }

    private function filterRegJourneyDates($request)
    {
        $body = [
            'startDate' => $request->startDate,
            'endDate' => $request->endDate
        ];

        $url = 'GetRegsJourney';

        $data = $this->postRequest($url, $body);

       if(!empty($data))
       {
            return (new RegJourney($data))->download('Registration-Journey.csv', \Maatwebsite\Excel\Excel::CSV, [
                'Content-Type' => 'text/csv',
            ]);
       }

       return null;
    }

    private function filterSIMSwapDates($request)
    {
        $body = [
            'startDate' => $request->startDate,
            'endDate' => $request->endDate
        ];

        $url = 'GetSimSwapReport';

        $data = $this->postRequest($url, $body);

        return (new SIMSwap($data))->download('SIM-Swap.csv', \Maatwebsite\Excel\Excel::CSV, [
            'Content-Type' => 'text/csv',
        ]);
    }

    public function filterReports(KYCReportsRequest $request)
    {
        if($request->reportType =='reg-journey')
        {
            return $this->filterRegJourneyDates($request);
        }
        else if($request->reportType =='sim-swap')
        {
            return $this->filterSIMSwapDates($request);
        }
    }




}
