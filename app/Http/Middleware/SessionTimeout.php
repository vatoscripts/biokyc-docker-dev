<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Session\Store;
use GuzzleHttp\Client;
use Log;
use Session;

class SessionTimeout
{
    protected $session;
    protected $timeout = 18000;
    protected $user;

    public function __construct(Store $session)
    {
        $this->session = $session;
        $this->user = $session->get('user');
    }

    /*
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (!$this->session->has('lastActivityTime')) {
            $this->session->put('lastActivityTime', time());
        } elseif ((time() - $this->session->get('lastActivityTime')) > $this->timeout) {
            $this->logout();
            return redirect()->guest(route('login'))->with('warning', 'Your session has expired !');
        }

        $this->session->put('lastActivityTime', time());

        return $next($request);
    }

    private function logout()
    {
        $headers = [
            'Content-Type' => 'application/json',
            'Authorization' => 'bearer ' . $this->user['Token'],
        ];

        $client = new Client([
            'headers' => $headers
        ]);

        $url = 'LogOut';

        $body = ['UserID' => $this->user['UserID']];

        $response = $client->request('POST', env('API_URL') . $url, ['json' => $body]);

        session::flush();
    }
}
