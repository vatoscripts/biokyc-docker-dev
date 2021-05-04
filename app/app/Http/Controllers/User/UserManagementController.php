<?php

namespace App\Http\Controllers\User;

use Illuminate\Http\Request;
use App\Http\Controllers\GuzzleController as GuzzleController;
use PhpParser\Node\Stmt\TryCatch;
use League\Flysystem\Exception;
use App\Http\Requests\KycRequest;
use App\Http\Requests\AgentOnboardRequest;
use Illuminate\Support\Facades\Log;

class UserManagementController extends GuzzleController
{
    public function __construct()
    {
        parent::__constructor();
        $this->middleware(['role:ROLE_ADMIN']);
    }

    public function index()
    {
        return view('permissions.user-management')->with([
            'users' => $this->getAllUsers(),
            'roles' => $this->getUserRoles(),
            'levels' => $this->getUserLevels(),
            'groups' => $this->getUserGroups(),
        ]);
    }

    public function getAllUsers()
    {
        $url = 'GetAllUsers';

        return $this->getRequest($url);
    }

    public function getUserRoles()
    {
        $url = 'GetUserRoles';

        return $this->getRequest($url);
    }

    public function getUserLevels()
    {
        $url = 'GetLevels';

        return $this->getRequest($url);
    }

    public function getUserGroups()
    {
        $url = 'GetUserGroups';

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

    public function saveUserManagement(Request $request)
    {
        $body = [
            'ModifiedBy' => $this->user['UserID'],
            'RoleID' => (int) $request->get('user-role-management'),
            'Level' => (int) $request->get('user-level-management'),
            'GroupID' => (int) $request->get('user-group-management'),
            'UserID' => (int) $request->get('user-management-radio'),
        ];

        $url = 'UpdateUserAccess';
        $data = $this->postRequest($url, $body);

        if ($data['ID'] === 0) {
            return redirect()->route('user.management')->with('success', 'Successful User Management Saved ');
        } else {
            return back()->withErrors('Oops! Could not complete Onboarding. Please Try again!');
        }

        return back()->withErrors('Oops! Could not complete Onboarding. Please Try again!');
    }

    public function ShowCreateNewUser() {
        $url = 'GetUserRoles';
        $data = $this->getRequest($url);

        $url2 = 'GetUsersList';
        $users = $this->getRequest($url2);

        return view('users.create-new')->with(['roles'=> $data, 'users' => $users]);
    }

    public function CreateNewUser(Request $request)
    {
        $messages = [
            'userName.required' => 'Please Input UserName !',
            'mobile-phone.required' => 'Please Input User\'s Phone Number !',
            'mobile-phone.regex' => 'Invalid User\'s Phone Number !',
            'email.required' => 'Please Input User\'s Email Adress !',
            'email.email' => 'Invalid User\'s Email Adress !',
            'roleName.required' => 'Please Select User\'s Role !',
        ];

        $this->validate($request, [
            'userName' => 'required',
            'mobile-phone' => 'required|regex:/\+?(255)-?([0-9]{3})-?([0-9]{6})/',
            'email' => 'required|email',
            'roleName' => 'required',
        ], $messages);


        $body = [
            'CreatedBy' => $this->user['UserID'],
            'username' => $request->userName,
            'phone' => $request->get('mobile-phone'),
            'email' => $request->email,
            'IsAD' => 'Y',
            'ActiveYN' => 'Y',
            'roleID' => (int) $request->roleName,
        ];

        $url = 'CreateUser';

        $data = $this->postRequest($url, $body);

        if ($data['ID'] !== 0) {
            return response()
                ->json([
                    'message' => $data['Description'],
                    'status' => $data['ID']
                ], 400);
        } elseif ($data['ID'] == 0) {
            return response()
                ->json([
                    'message' => 'User Successful Created !',
                    'status' => $data['ID']
                ], 200);
        } elseif ($data['ID'] == 2) {
            return response()
                ->json([
                    'message' => 'User already exists in the system !',
                    'status' => $data['ID']
                ], 200);
        }

        return response()
            ->json([
                'message' => 'Sorry, Something went wrong . Try again !',
            ], 400);
    }
}
