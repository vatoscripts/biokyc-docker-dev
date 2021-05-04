<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\View;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Session;
use Exception;
use Guzzle\Http\Exception\BadResponseException;
use Guzzle\Http\Exception\ClientErrorResponseException;
use Guzzle\Http\Exception\ServerErrorResponseException;

class GuzzleController extends Controller
{
    public $user;
    public $redis;
    private $container = [];
    private $client;

    //Constructor method
    public function __constructor()
    {
        //$this->redis =  Redis::connection();

        $this->middleware(function ($request, $next) {
            if (session::has('user')) {
                $this->user = session::get('user');
                // Sharing is caring
                View::share('user', $this->user);
            } else {
                $this->user = NULL;
            }

            return $next($request);
        });

        $history = Middleware::history($this->container);

        $stack = HandlerStack::create();
        // Add the history middleware to the handler stack.
        $stack->push($history);

        if (is_array($this->user)) {
            $bearer = $this->user['Token'];
        } else {
            $bearer = '';
        }


        $headers = [
            'Content-Type' => 'application/json',
            'Authorization' =>  $bearer,
        ];

        $this->client = new Client([
            'headers' => $headers,
            'base_uri' => env('API_URL'),
            'handler' => $stack
        ]);
    }

    protected function postRequest($url, $body)
    {
        try {
            $response = $this->client->request('POST', $url, ['json' => $body]);
            return json_decode($response->getBody()->getContents(), true);
        } catch (Exception $e) {
            //Log::debug(Psr7\Message::toString($e->getRequest()));
            if ($e->hasResponse()) {
                $response = $e->getResponse();

                Log::channel('Guzzle')->critical([
                    'Request' => Psr7\Message::toString($e->getRequest()),
                    'Response' => Psr7\Message::toString($e->getResponse()),
                ]);

                // $response = $e->getResponse();
                // $responseBodyAsString = $response->getBody()->getContents();
                // Log::notice($responseBodyAsString);
                // Log::info(Psr7\Message::toString($e->getResponse()));
            }

            foreach ($this->container as $transaction) {
                Log::channel('Exception')->critical([
                    'Body' => (string) $transaction['request']->getBody(),
                    'Request' => $transaction['request'],
                ]);
            }

            throw new Exception($e);
        }
    }

    protected function getRequest($url)
    {
        try {
            $response = $this->client->request('GET', $url);
            return json_decode($response->getBody()->getContents(), true);
        } catch (ClientErrorResponseException | ServerErrorResponseException | BadResponseException $e) {
            if ($e->hasResponse()) {
                $response = $e->getResponse();
                $responseBodyAsString = $response->getBody()->getContents();
                Log::channel('Guzzle')->emergency(['user' => $this->user['UserName'], 'Response' => $responseBodyAsString]);
            }
            throw new Exception($e);
        } catch (Exception $e) {
            foreach ($this->container as $transaction) {
                Log::channel('Exception')->critical([
                    'Body' => (string) $transaction['request']->getBody(),
                    'Request' => $transaction['request'],
                    //'error' => $this->container
                ]);
            }
            //throw new Exception($e->getResponse()->getBody()->getContents());
            //Log::critical($e);
            throw new Exception($e);
        }
    }
}
