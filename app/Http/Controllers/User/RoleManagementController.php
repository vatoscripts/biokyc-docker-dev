<?php

namespace App\Http\Controllers\User;

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

class RoleManagementController extends GuzzleController
{
    //
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN']);
    }

    public function index()
    {
        return view('permissions.role-management')->with([
            'roles' => $this->getUserRoles()
        ]);
    }

    public function getUserRights()
    {
        $url = 'GetUserRights';

        return $this->getRequest($url);
    }

    public function getUserRoles()
    {
        $url = 'GetUserRoles';

        return $this->getRequest($url);
    }

    public function getUserRightbyRoles($Id)
    {
        $url = 'GetUserRightsByRoleID/' . $Id;

        return $this->getRequest($url);
    }

    public function saveRoleRights(Request $request)
    {
        $url = 'RoleUserRights';

        $data = $this->postRequest($url, $request->toArray());

        return $data;
    }
}
