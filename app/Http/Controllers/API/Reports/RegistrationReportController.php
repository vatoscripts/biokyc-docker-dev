<?php

namespace App\Http\Controllers\API\Reports;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Controllers\GuzzleController as GuzzleController;
use App\Http\Requests\ReportRequest;
use Illuminate\Support\Facades\Log;
use Session;
use Route;

class RegistrationReportController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN,ROLE_BACK_OFFICE,ROLE_FORENSIC']);
    }

    public function registrationReport(ReportRequest $request)
    {
         $body = [
            'startdate' => $request->startDate,
            'enddate' => $request->endDate,
            'reportnameID' => (int) $request->reportCategory,
            'email' => $this->user['Email'],
        ];

        $url = 'ExportReport';

        $data = $this->postRequest($url, $body);

        return response()->json(null, 200);
    }

    public function getRegistrationReportCategories()
    {
        $url = 'GetReportNames';

        $categories = $this->getRequest($url);

        return response()->json($categories, 200);
    }
}
