<?php

namespace App\Http\Controllers\Support;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Http\Controllers\GuzzleController as GuzzleController;
use Session;
use PDF;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use ZipArchive;
use Spatie\Async\Pool;

class KYASupportController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN,ROLE_FORENSIC'])->only(['viewUserDetails', 'getUserDetails', 'viewUserBlock','blockUser','unblockUser', 'viewUserUnblock' ]);
        $this->middleware(['role:ROLE_ADMIN,ROLE_SUPPORT_OFFICER,ROLE_BACK_OFFICE,ROLE_FORENSIC'])->except(['viewUserDetails', 'getUserDetails', 'viewUserBlock','blockUser','unblockUser', 'viewUserUnblock' ]);
    }

    public function viewStaffAccountDetails()
    {
        return view('support.kya.staff-account-details');
    }

    public function getStaffAccountDetails(Request $request)
    {
        $messages = [
            'username.required' => 'Please Enter Agent Staff Username',
            'username.regex' => 'Please Enter valid Agent Staff Username e.g 2557547000000',
        ];

        $this->validate($request, [
            'username' => 'required|regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})$/'
        ], $messages);

        $body = [
            'Msisdn' => $request->username
        ];

        $url = 'GetAgentStaffAccountDetails';

        $data = $this->postRequest($url, $body);

        return response()->json($data, 200);
    }

    public function viewUserDetails()
    {
        session::forget(['userID', 'status']);
        return view('support.kya.user-details');
    }

    public function getUserDetails(Request $request)
    {
        $messages = [
            'username.required' => 'Please input Username',
            'username.regex' => 'Please Enter valid Agent Staff Username e.g 2557547000000',
        ];

        $this->validate($request, [
            'username' => 'required|regex:/^(255)-?([0-9]{3})-?([0-9]{6})$/'
        ], $messages);

        $body = [
            'Msisdn' => $request->username
        ];

        $url = 'GetusersForActivation?username=' .$request->username;

        $data = $this->getRequest($url);

        session::put(['userID'=> $data[0]['UserID'], 'status'=> $data[0]['ActiveYN'] ] );

        return response()->json($data, 200);
    }

    public function viewUserBlock()
    {
        return view('support.kya.user-block');
    }

    public function blockUser(Request $request)
    {
        $messages = [
            'blockReason.required' => 'Please specify your reason for blocking this user !',
            'block-reason-text.required' => 'Please input reason !'
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

        $url = 'UserActivation';

        $body = [
            'UserID' => (int) $request->input('userId'),
            'Reason' => $reason,
            'ActionID' => 0,
            'ActionedBy' => $this->user['UserID'],
            'Reference' => $request->blockReference
        ];

        $data = $this->postRequest($url, $body);

        if ($data['ID'] !== 0 || $data['Description'] !== null) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] === 0 && $data['Description'] === null) {
            session::forget(['userID', 'status']);
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 200);
        }

        return response()->json(['message' => 'An error occured !','status' => $data], 400);
    }

    public function viewUserUnblock()
    {
        return view('support.kya.user-unblock');
    }

    public function unblockUser(Request $request)
    {
        $messages = [
            'unblockReason.required' => 'Please specify your reason for unblocking this user !'
        ];

        $this->validate($request, [
            'unblockReason' => 'required',
        ], $messages);

        $reason = $request->input('unblockReason');

        $url = 'UserActivation';

        $body = [
            'UserID' => (int) $request->input('userId'),
            'Reason' => $reason,
            'ActionID' => 1,
            'ActionedBy' => $this->user['UserID'],
            'Reference' => $request->unblockReference
        ];

        $data = $this->postRequest($url, $body);

        return response()->json($data, 200);

        if ($data['ID'] !== 0 || $data['Description'] !== null) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] === 0 && $data['Description'] === null) {
            session::forget(['userID', 'status']);
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 200);
        }

        return response()->json(['message' => 'An error occured !','status' => $data], 400);
    }

    public function viewAgentStaffID($id=null)
    {
        $id = 320;

        $url = 'AgentStaff/'. $id;

        $data = $this->getRequest($url);

        return view('support.kya.staff-id.view')->with('staff', $data );
    }

    public function viewAgentStaffIDPDF($id=null)
    {
        $id = 320;

        $url = 'AgentStaff/'. $id;

        $data = $this->getRequest($url);

        return view('support.kya.staff-id.view-pdf')->with('staff', $data );
    }


    public function downloadAgentStaffIDPDF($id=null)
    {
        $id = 2;

        $url = 'GetDigitalIDs?no='. $id;

        $data = $this->getRequest($url);

        $directory = 'digital-ids/';

        $pool = Pool::create();

        foreach($data as $key => $value) {
            $pool[] = async(function () use ($value) {
                view()->share('staff',$value);

                $pdf = PDF::loadView('support.kya.staff-id.download-pdf', $value)->setPaper('a6');

                $pdf_name = Str::random(32).".pdf";

                Storage::put('digital-ids/'.$pdf_name, $pdf->output());
                })->then(function () {
                print_r('Finished :'  . "\n");
            });
        }

        await($pool);

        // $zipname = 'digital-ids.zip';
        // $path = storage_path('app/digital-ids');
        // $zip = new \ZipArchive();
        // $zip->open($zipname, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);

        // $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));
        // foreach ($files as $name => $file)
        // {
        //     // We're skipping all subfolders
        //     if (!$file->isDir()) {
        //         $filePath     = $file->getRealPath();

        //         // extracting filename with substr/strlen
        //         $relativePath = 'digital-ids/' . substr($filePath, strlen($path) + 1);

        //         $zip->addFile($filePath, $relativePath);
        //     }
        // }
        // $zip->close();

        // return response()->download($zipname);



        //echo $this->createZipAndDownload($files, $path, $zipname);

        //$fileName = 'my-archive.zip';

        //$files_to_zip = ['demo1.jpg', 'demo2.jpg'];

        //$result = $this->createZip($files, $path);


        // header("Content-Disposition: attachment; filename=\"".$zipname."\"");

        // header("Content-Length: ".filesize($zipname));

        // readfile($zipname);

    }

    function createZipAndDownload($files, $filesPath, $zipFileName)
    {
        // Create instance of ZipArchive. and open the zip folder.
        $zip = new \ZipArchive();
        if ($zip->open($zipFileName, \ZipArchive::CREATE) !== TRUE) {
            exit("cannot open <$zipFileName>\n");
        }

        // Adding every attachments files into the ZIP.
        foreach ($files as $file) {
            $zip->addFile($filesPath . $file, $file);
        }
        $zip->close();

        // Download the created zip file
        header("Content-type: application/zip");
        header("Content-Disposition: attachment; filename = $zipFileName");
        header("Pragma: no-cache");
        header("Expires: 0");
        readfile("$zipFileName");
        exit;
    }

    /* create a compressed zip file */
    function createZip($files = array(), $destination = '', $overwrite = false) {
        if(file_exists($destination) && !$overwrite) { return false; }

        $validFiles = [];

        if(is_array($files)) {
            foreach($files as $file) {
                if(file_exists($file)) {
                    $validFiles[] = $file;
                }
            }
        }

        if(count($validFiles)) {
            $zip = new ZipArchive();
            if($zip->open($destination,$overwrite ? ZIPARCHIVE::OVERWRITE : ZIPARCHIVE::CREATE) !== true) {
                return false;
            }

            foreach($validFiles as $file) {
                $zip->addFile($file,$file);
            }

            $zip->close();

            return file_exists($destination);
        }else{
            return false;
        }
    }

}
