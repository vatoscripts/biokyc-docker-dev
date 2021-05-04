<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Redis;

class CheckAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $redis = Redis::connection();
        $user = $request->session()->get('user');

        if (is_array($user)) {
            $key = 'user:' . $user['UserName'];
        } else {
            $key = null;
        }

        if (!$request->session()->exists(['user', 'Authenticated'])) {
            $request->session()->flush();
            return redirect()->route('login')->withWarning('Your Session has expired !');
        }

        if ($redis->exists($key)) {
            $oldUser = $redis->hgetall($key);
            if ($oldUser['token'] === $user['Token']) {
                return $next($request);
            }
        }

        $request->session()->flush();
        return redirect()->route('login')->withWarning('Your session has been terminated by another log-in attempt !');
    }
}
