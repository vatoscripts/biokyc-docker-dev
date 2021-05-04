<?php

use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\SyslogUdpHandler;

return [

    /*
    |--------------------------------------------------------------------------
    | Default Log Channel
    |--------------------------------------------------------------------------
    |
    | This option defines the default log channel that gets used when writing
    | messages to the logs. The name specified in this option should match
    | one of the channels defined in the "channels" configuration array.
    |
    */

    'default' => env('LOG_CHANNEL', 'stack'),

    /*
    |--------------------------------------------------------------------------
    | Log Channels
    |--------------------------------------------------------------------------
    |
    | Here you may configure the log channels for your application. Out of
    | the box, Laravel uses the Monolog PHP logging library. This gives
    | you a variety of powerful log handlers / formatters to utilize.
    |
    | Available Drivers: "single", "daily", "slack", "syslog",
    |                    "errorlog", "monolog",
    |                    "custom", "stack"
    |
    */

    'channels' => [
        'stack' => [
            'driver' => 'stack',
            'channels' => ['daily'],
            'ignore_exceptions' => false,
        ],

        'New-Reg' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/new-reg.log'),
            'level' => 'emergency',
        ],

        'Re-Reg' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/re-reg.log'),
            'level' => 'emergency',
        ],

        'New-foreigner' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/new-foreigner.log'),
            'level' => 'emergency',
        ],

        'Re-Reg-foreigner' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/re-reg-foreigner.log'),
            'level' => 'emergency',
        ],

        'SIM-swap' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/sim-swap.log'),
            'level' => 'emergency',
        ],

        'Total-mismatch' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/total-mismatch.log'),
            'level' => 'emergency',
        ],

        'New-defaced' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/new-defaced.log'),
            'level' => 'emergency',
        ],

        'Re-Reg-defaced' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/re-reg-defaced.log'),
            'level' => 'emergency',
        ],

        'Bulk-Reg-nida' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/bulk-registration/nida.log'),
            'level' => 'debug',
        ],

        'Bulk-Reg-primary' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/bulk-registration/primary.log'),
            'level' => 'debug',
        ],

        'Bulk-Reg-secondary' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/bulk-registration/secondary.log'),
            'level' => 'debug',
        ],

        'Single-Diplomat-Reg' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/single-diplomat-reg.log'),
            'level' => 'emergency',
        ],

        'Bulk-Diplomat-Reg' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/bulk-diplomat-reg.log'),
            'level' => 'emergency',
        ],

        'De-Reg-Nida' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/De-registration/nida.log'),
            'level' => 'debug',
        ],

        'De-Reg-Msisdn' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/De-registration/msisdn.log'),
            'level' => 'debug',
        ],

        'De-Reg-Code' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/De-registration/code.log'),
            'level' => 'debug',
        ],

        'Registral' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYA/staff.log'),
            'level' => 'debug',
        ],

        'Agent' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYA/agent.log'),
            'level' => 'emergency',
        ],

        'Recruiter' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYA/recruiter.log'),
            'level' => 'debug',
        ],

        'Guzzle' => [
            'driver' => 'daily',
            'path' => storage_path('logs/Guzzle/Guzzle.log'),
            'level' => 'debug',
        ],

        'Exception' => [
            'driver' => 'daily',
            'path' => storage_path('logs/Exception/Exception.log'),
            'level' => 'debug',
        ],

        'Logout' => [
            'driver' => 'daily',
            'path' => storage_path('logs/User/Logout.log'),
            'level' => 'debug',
        ],

        'Primary-msisdn-first' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/primary-msisdn/first-page.log'),
            'level' => 'debug',
        ],

        'Primary-msisdn-second' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/primary-msisdn/second-page.log'),
            'level' => 'debug',
        ],

        'Secondary-msisdn-first' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/secondary-msisdn/first-page.log'),
            'level' => 'debug',
        ],

        'Secondary-msisdn-second' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/secondary-msisdn/second-page.log'),
            'level' => 'debug',
        ],

        'New-msisdn-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/new-msisdn.log'),
            'level' => 'debug',
        ],

        'Primary-msisdn-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/primary-msisdn.log'),
            'level' => 'debug',
        ],

        'Secondary-msisdn-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/secondary-msisdn.log'),
            'level' => 'debug',
        ],

        'Primary-msisdn-other-first' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/primary-msisdn/other-first-page.log'),
            'level' => 'debug',
        ],

        'Primary-msisdn-other-second' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/primary-msisdn/other-second-page.log'),
            'level' => 'debug',
        ],

        'Secondary-msisdn-other-first' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/secondary-msisdn/other-first-page.log'),
            'level' => 'debug',
        ],

        'Secondary-msisdn-other-second' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/secondary-msisdn/other-second-page.log'),
            'level' => 'debug',
        ],

        'New-msisdn-diplomat-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/diplomat/new-msisdn.log'),
            'level' => 'debug',
        ],

        'Primary-msisdn-diplomat-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/diplomat/primary-msisdn.log'),
            'level' => 'debug',
        ],

        'Secondary-msisdn-diplomat-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/diplomat/secondary-msisdn.log'),
            'level' => 'debug',
        ],

        'New-msisdn-visitor-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/visitor/new-msisdn.log'),
            'level' => 'debug',
        ],

        'Primary-msisdn-visitor-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/visitor/primary-msisdn.log'),
            'level' => 'debug',
        ],

        'Secondary-msisdn-visitor-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/visitor/secondary-msisdn.log'),
            'level' => 'debug',
        ],

        'Minor-check' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/minor/check-msisdn.log'),
            'level' => 'debug',
        ],

        'Minor-register' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/minor/register-msisdn.log'),
            'level' => 'debug',
        ],

        'Bulk-declaration' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/bulk/bulk-declaration.log'),
            'level' => 'debug',
        ],

        'Visitor-alt-register-review' => [
            'driver' => 'daily',
            'path' => storage_path('logs/KYC/one-sim/visitor/alternative-reg-review.log'),
            'level' => 'debug',
        ],


        'single' => [
            'driver' => 'single',
            'path' => storage_path('logs/laravel.log'),
            'level' => 'debug',
        ],

        'daily' => [
            'driver' => 'daily',
            'path' => storage_path('logs/laravel.log'),
            'level' => 'debug',
            'days' => 14,
        ],

        'slack' => [
            'driver' => 'slack',
            'url' => env('LOG_SLACK_WEBHOOK_URL'),
            'username' => 'Laravel Log',
            'emoji' => ':boom:',
            'level' => 'critical',
        ],

        'papertrail' => [
            'driver' => 'monolog',
            'level' => 'debug',
            'handler' => SyslogUdpHandler::class,
            'handler_with' => [
                'host' => env('PAPERTRAIL_URL'),
                'port' => env('PAPERTRAIL_PORT'),
            ],
        ],

        'stderr' => [
            'driver' => 'monolog',
            'handler' => StreamHandler::class,
            'formatter' => env('LOG_STDERR_FORMATTER'),
            'with' => [
                'stream' => 'php://stderr',
            ],
        ],

        'syslog' => [
            'driver' => 'syslog',
            'level' => 'debug',
        ],

        'errorlog' => [
            'driver' => 'errorlog',
            'level' => 'debug',
        ],

        'null' => [
            'driver' => 'monolog',
            'handler' => NullHandler::class,
        ],

        'emergency' => [
            'path' => storage_path('logs/laravel.log'),
        ],
    ],

];
