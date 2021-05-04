<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Session\Store;
use Illuminate\Auth\Access\AuthorizationException;

class CheckRole
{
    protected $user;
    protected $session;

    public function __construct(Store $session)
    {
        $this->user = $session->get('user');
        $this->session = $session;;
        //dd($this->user);
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next, ...$role)
    {
        //dd($role);
        if (!$this->hasAnyRole($role)) {

            throw new AuthorizationException('You do not have permission to view this page');
        }

        return $next($request);
    }

    public function hasAnyRole($roles)
    {
        //dd($roles);
        if (is_array($roles)) {

            foreach ($roles as $role) {
                if ($this->hasRole($role)) {
                    return TRUE;
                }
            }
        } elseif ($this->hasRole($roles)) {
            return TRUE;
        }
        return FALSE;
    }

    public function hasRole($role)
    {
        $user = $this->session->get('user');
        if ($user['Role'] == $this->getRole($role)) {
            return TRUE;
        }
        return FALSE;
    }

    public function getRole($roleID)
    {
        switch ($roleID) {
            case 'ROLE_REGISTRAL':
                return 1;
                break;
            case 'ROLE_ADMIN':
                return 2;
                break;
            case 'ROLE_AGENT':
                return 3;
                break;
            case 'ROLE_STAFF_RECRUITER':
                return 4;
                break;
            case 'ROLE_BACK_OFFICE':
                return 5;
                break;
			case 'ROLE_SHOP_MANAGER':
                return 6;
                break;
			case 'ROLE_SPECIAL_REGISTRAL':
                return 7;
                break;
			case 'ROLE_SUPPORT_OFFICER':
                return 8;
                break;
            case 'ROLE_FORENSIC':
                return 9;
                break;
            case 'ROLE_MAKER':
                return 11;
                break;
            case 'ROLE_CHECKER':
                return 12;
                break;
            default:
                # code...
                break;
        }
    }
}
