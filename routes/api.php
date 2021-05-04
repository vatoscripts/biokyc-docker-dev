<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

Route::group(['middleware' => [
    //'check-auth',
    'SessionTimeout'
]], function () {
    Route::post('one-sim/bulk/new-reg-post', 'API\Registration\BulkRegistrationController@postBulkRegistrationStart')->name('api.register.bulk.post');
    Route::post('one-sim/bulk/new-reg-search', 'API\Registration\BulkRegistrationController@postBulkRegistrationSearch')->name('api.register.bulk.post.search');
    Route::post('one-sim/bulk/primary-spoc', 'API\Registration\BulkRegistrationController@bulkSpocRegistration')->name('api.register.bulk.primary.spoc.post');
    Route::post('one-sim/bulk/primary-register', 'API\Registration\BulkRegistrationController@bulkPrimaryRegistration')->name('api.register.bulk.company');

    Route::post('one-sim/bulk/company-search', 'API\Registration\BulkRegistrationController@bulkRegistrationSecondarySearch')->name('api.register.bulk.company.search');
    Route::post('one-sim/bulk/secondary-register', 'API\Registration\BulkRegistrationController@bulkSecondaryRegistration')->name('api.register.bulk.secondary');

    Route::post('one-sim/bulk/declaration', 'API\Registration\BulkRegistrationController@bulkDeclaration')->name('api.declaration.bulk');

    Route::post('one-sim/minor/check-msisdn', 'API\RegistrationController@registerMinorCheck')->name('api.register.minor.check');
    Route::post('one-sim/minor/register', 'API\RegistrationController@registerMinor')->name('api.register.minor');

    Route::post('primary/check-msisdn', 'API\RegistrationController@checkPrimary')->name('api.primary.check');
    Route::get('primary/get-msisdn', 'API\RegistrationController@getMsisdnPrimary')->name('api.primary.list');
    Route::post('primary/set-msisdn', 'API\RegistrationController@setPrimary')->name('api.primary.set');

    Route::post('secondary/check-msisdn', 'API\RegistrationController@checkSecondary')->name('api.secondary.check');
    Route::get('secondary/get-msisdn', 'API\RegistrationController@getMsisdnSecondary')->name('api.secondary.list');
    Route::post('secondary/set-msisdn', 'API\RegistrationController@setSecondary')->name('api.primary.set');

    Route::post('diplomat/check-msisdn', 'API\RegistrationController@diplomatCheck')->name('api.diplomat.check');
    Route::post('diplomat/register-primary', 'API\RegistrationController@diplomatRegisterPrimary')->name('api.diplomat.register.primary');
    Route::post('diplomat/register-secondary', 'API\RegistrationController@diplomatRegisterSecondary')->name('api.diplomat.register.primary');

    Route::post('nida/check-msisdn', 'API\RegistrationController@checkMsisdnNIDA')->name('api.nida.check');
    Route::post('nida/register-primary', 'API\RegistrationController@registerPrimaryNIDA')->name('api.nida.primary.register');
    Route::post('nida/register-secondary', 'API\RegistrationController@registerSecondaryNIDA')->name('api.nida.secondary.register');

    Route::post('visitor/check-msisdn', 'API\RegistrationController@checkMsisdnVisitor')->name('api.visitor.check');
    Route::post('visitor/register-primary', 'API\RegistrationController@registerPrimaryVisitor')->name('api.visitor.primary.register');
    Route::post('visitor/register-secondary', 'API\RegistrationController@registerSecondaryVisitor')->name('api.visitor.secondary.register');

    Route::get('/regions', 'API\RegistrationController@getRegions')->name('regions');
    Route::get('/districts/{Id}', 'API\RegistrationController@getDistrict')->name('districts');
    Route::get('/wards/{Id}', 'API\RegistrationController@getWard')->name('wards');
    Route::get('/villages/{id}', 'API\RegistrationController@getVillage')->name('villages');

    Route::get('/diplomat-countries', 'API\RegistrationController@getCountryList')->name('diplomat.countries');
    Route::get('/immigration-countries', 'API\RegistrationController@ImmigrationCountryList')->name('immigration.countries');

    Route::post('dereg/nida', 'API\RegistrationController@deregNIDA')->name('api.dereg.nida');
    Route::post('dereg/msisdn', 'API\RegistrationController@deregMsisdn')->name('api.dereg.msisdn');
    Route::post('dereg/code', 'API\RegistrationController@deregCode')->name('api.dereg.code');
    Route::get('dereg/get-msisdn', 'API\RegistrationController@getDeregMsisdn')->name('api.dereg.list');

    /**
     * REPORTS
     */
    Route::post('reports/kyc', 'API\Reports\RegistrationReportController@registrationReport')->name('api.reg-reports');
    Route::get('/reports/kyc/categories', 'API\Reports\RegistrationReportController@getRegistrationReportCategories')->name('api.reg-reports.categories');

    /** SUPPORT ROUTES */
    Route::post('support/reg-details-id', 'API\Support\KYCSupportController@registrationPerID')->name('api.registration.details.id');
    Route::get('support/visitor-alternative-registrations', 'API\Support\KYCSupportController@getAllAltVisitorRegs')->name('api.visitor.alternative');
    Route::post('support/visitor-alternative-registrations/single', 'API\Support\KYCSupportController@getSingleAltVisitorRegs')->name('api.single.visitor.alternative');
    Route::post('support/visitor-alternative-registrations/review', 'API\Support\KYCSupportController@reviewVisitorAlternativeReg')->name('api.registvisitor.alternative.review');
});
