<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/


// Put routes in here
Route::get('/', 'User\UserController@showLoginForm')->name('login');
Route::get('/login', 'User\UserController@showLoginForm')->name('login');

Route::post('login', 'User\UserController@login');

Route::get('/reset-password', 'User\UserController@showResetPassword')->name('reset.password');
Route::post('/reset-password', 'User\UserController@getResetPassowordToken');

Route::get('/reset-password/{token}', 'User/UserController@verifyResetPasswordToken')->name('reset.password.token');

Route::get('/recover-password', 'User\UserController@showRecoverPassword')->name('recover.password');
Route::post('/recover-password', 'User\UserController@RecoverPassword');

Route::get('/recover-new-password', 'User\UserController@showRecoverNewPassword')->name('recover.new.password');
Route::post('/recover-new-password', 'User\UserController@RecoverNewPassword');

Route::get('/recover-password-sms', 'User\UserController@showRecoverPasswordSMS')->name('recover.password.sms');
Route::post('/recover-password-sms', 'User\UserController@RecoverPasswordSMS');

Route::get('/list-users', 'User\UserController@ShowCreateNewUser')->name('list.users');
Route::post('/create-user-post', 'User\UserController@CreateNewUser');

//Route::get('/test-page', 'UserController@ShowtestPage')->name('list.users');

// Route::get('support/view-staff-id-pdf', 'Support\KYASupportController@viewAgentStaffIDPDF')->name('digital.id.view');

Route::get('support/download/staff-id-pdf', 'Support\KYASupportController@downloadAgentStaffIDPDF')->name('digital.id.download');

Route::get('/test-page', 'DashboardController@showMyArray');

/*
|---------------------------------------------------------------------------------
| Begin OTP routes
|--------------------------------------------------------------------------------
*/
Route::group(['middleware' => ['check-user']], function () {
    Route::post('/otp', 'User\UserController@validateOtp')->middleware('check-user');
    Route::get('/otp', 'User\UserController@showOTPForm')->name('otp')->middleware('check-user');
    Route::get('/resend-otp', 'User\UserController@resendToken')->name('resendtoken')->middleware('check-user');
});
/*
|---------------------------------------------------------------------------------
| End OTP routes
|--------------------------------------------------------------------------------
*/

Route::namespace('Admin')->group(function () {
    // Controllers Within The "App\Http\Controllers\Admin" Namespace
});

Route::namespace('Admin')->group(function () {
    // Controllers Within The "App\Http\Controllers\Admin" Namespace
});

/*
|---------------------------------------------------------------------------------
| Begin KYA routes
|--------------------------------------------------------------------------------
*/

Route::group(['namespace' => 'KYA', 'middleware' => [
    //'check-auth',
    'SessionTimeout'
]], function () {
    Route::get('/agents', 'AgentsController@index')->name('agents');
    Route::get('/agent/{id}', 'AgentsController@getAgentDetails')->name('agent.details');

    Route::get('/zone', 'AgentsController@getZones')->name('agent.zones');
    Route::get('/region/{Id}', 'AgentsController@getRegions')->name('agent.regions');
    Route::get('/territory/{Id}', 'AgentsController@getTerritory')->name('agent.territory');
    Route::post('/AgentAddress', 'AgentsController@postAgentAddress')->name('agent.post.AgentAddress');

    Route::post('/agents-nida', 'AgentsController@createAgentQueryNIDA')->name('agent.post.create');

    Route::get('/create-agent', 'AgentsController@createAgentDB')->name('agent.post.create');
    Route::post('/create-agent', 'AgentsController@createAgentDB')->name('agent.post.create');

    Route::get('/block-agent/{Id}', 'AgentsController@blockAgent')->name('agent.post.block');

    Route::get('/unblock-agent/{Id}', 'AgentsController@unBlockAgent')->name('agent.post.block');

    Route::get('/agent-staff', 'AgentStaffController@index')->name('agentstaff');
    Route::get('/agent-staff/{Id}', 'AgentStaffController@getAgentStaffDetails')->name('agentstaff.details');

    Route::get('/agentstaff-nida', 'AgentStaffController@createAgentStaffQuery')->name('agent-staff.post.create');
    Route::post('/agentstaff-nida', 'AgentStaffController@createAgentStaffDB')->name('agent.staff.create');

    //Route::get('/block-agentstaff/{Id}', 'AgentStaffController@blockAgentStaff')->name('agentstaff.block');
    Route::post('/block-agentstaff', 'AgentStaffController@blockAgentStaff')->name('agentstaff.block');

    //Route::get('/unblock-agentstaff/{Id}', 'AgentStaffController@unBlockAgentStaff')->name('agentstaff.unblock');
    Route::post('/unblock-agentstaff', 'AgentStaffController@unBlockAgentStaff')->name('agentstaff.unblock');

    Route::get('/staff-verify-ims/{Id}', 'AgentStaffController@getverifyAgentIMS')->name('agent.staff.create');
    Route::post('/staff-verify-ims/', 'AgentStaffController@verifyAgentIMS1')->name('agent.staff.create');
    Route::post('/staff-onboard-ims', 'AgentStaffController@onboardAgentIMS1')->name('agent.staff.create.post');
    Route::get('/staff-onboard-ims', 'AgentStaffController@getonboardAgentIMS')->name('agent.staff.onboard');

    Route::get('/staff-regions', 'AgentStaffController@getRegions')->name('staff.region');
    Route::get('/staff-region/{Id}', 'AgentStaffController@getRegionId')->name('staff.region');
    Route::get('/staff-district/{Id}', 'AgentStaffController@getDistrict')->name('staff.district');
    Route::get('/staff-ward/{Id}', 'AgentStaffController@getWard')->name('staff.ward');
    Route::get('/staff-village/{Id}', 'AgentStaffController@getVillage')->name('staff.village');

    Route::post('/clearIMSDevice', 'AgentStaffController@clearIMSDevice')->name('agentstaff.device.clear');

    Route::get('/agent-staff-migrations', 'AgentStaffController@showstaffMigrate')->name('staff.village');
    Route::post('agent-staff-migrations', 'AgentStaffController@staffMigrate')->name('agentstaff.device.clear');

    Route::get('/agents-list', 'AgentsController@getAgentList')->name('agent.list');

    Route::get('/agent-category', 'AgentsController@getAgentCategory')->name('agent.category');

    Route::get('/agent-staff-recruiter', 'RecruiterController@index')->name('recruiter.list');
    Route::post('/create-staff-recruiter', 'RecruiterController@createStaffRecruiter')->name('recruiter.create');
    Route::get('/agent-staff-recruiter/{Id}', 'RecruiterController@viewRecruiter')->name('recruiter.view');
    Route::get('/block-staff-recruiter/{recruiterID}', 'RecruiterController@blockRecruiter')->name('recruiter.block');
    Route::get('/unblock-staff-recruiter/{recruiterID}', 'RecruiterController@unblockRecruiter')->name('recruiter.unblock');

    Route::get('/agent/shops/{Id}', 'AgentsController@showAgentShops')->name('agent.shops');
    Route::post('agent-shop-save', 'AgentsController@AgentShopSave')->name('agent.shops.save');

    Route::get('/agent/view', 'AgentsController@showAgentProfile')->name('agent.view');
    Route::get('/agentByUserID', 'AgentsController@getAgentByUser')->name('agent.shops');
    Route::get('/agentShops/{id}', 'AgentsController@getAgentShops')->name('agent.shops');

    Route::get('/recruiterByUserID', 'AgentStaffController@getRecruiterByUserID')->name('agent.shops');

    Route::get('/edit/agent/shops/{agentId}/{shopId}', 'AgentsController@editShop')->name('agent.shops.edit');

    Route::get('downloadData/', 'AgentsController@downloadData');
    Route::get('/getStaffByAgent/{Id}', 'AgentStaffController@getStaffByAgent')->name('staff.village');
});

Route::group(['middleware' => [
    //'check-auth',
    'SessionTimeout'
]], function () {

    Route::get('/home', 'Home\DashboardController@index2')->name('home');
    //Route::get('/home', 'DashboardController@index')->name('home');
    Route::get('/logout', 'User\UserController@logoutUser');

    Route::get('/customer-details/{id}', 'Home\DashboardController@getCustDetails')->name('customer.details');

    Route::get('/new-registration', 'KYC\KYCController@show_newReg')->name('new.reg');
    Route::post('/check-msisdn', 'KYC\KYCController@checkMSISDN_newReg')->name('check.msisdn.Icap');
    Route::post('/register-new-msisdn', 'KYC\KYCController@register_new_MSISDN_Icap')->name('check.msisdn.Icap');

    Route::get('/re-registration', 'KYC\KYCController@show_reReg')->name('re.reg');
    Route::post('/check-msisdn', 'KYC\KYCController@checkMSISDNIcap')->name('check.msisdn.Icap');
    Route::post('/re-register-msisdn', 'KYC\KYCController@re_register_MSISDN')->name('check.msisdn.Icap');

    Route::get('/new-registration', 'KYC\KYCController@show_newReg')->name('new.reg');
    Route::post('/recheck-msisdn', 'KYC\KYCController@recheckMSISDNIcap')->name('check.msisdn.Icap');
    Route::post('/register-new-msisdn', 'KYC\KYCController@register_new_MSISDN_Icap')->name('check.msisdn.Icap');


    Route::get('/search-registration', 'KYC\KYCController@searchRegistration')->name('search.reg');
    Route::post('/search-registration', 'KYC\KYCController@getCustomerDetails')->name('search.msisdn.details');

    Route::get('/defaced-re-registration', 'KYC\KYCController@getDefacedQuestion')->name('search.reg');
    Route::post('/defaced-re-reg-answer', 'KYC\KYCController@getDefacedAnswer')->name('search.msisdn.details');

    Route::get('/bulk-registration', 'KYC\BulkRegController@showBulkRegistrationForm')->name('bulk.reg');
    Route::post('/bulk-registration-NIDA', 'KYC\BulkRegController@processBulkRegistration_page1')->name('post.bulk.NIDA');
    Route::post('/bulk-registration-save', 'KYC\BulkRegController@processBulkRegistration_page2')->name('post.bulk.NIDA');

    Route::get('/sim-swap-registration', 'KYC\KYCController@showSIMSwapPage')->name('sim-swap.reg');
    Route::post('/sim-swap-msisdn', 'KYC\KYCController@checkMSISDN_SIMSwap')->name('sim-swap.msisdn');
    Route::post('/sim-swap-save', 'KYC\KYCController@saveSIMSwapReg')->name('sim-swap.save');

    Route::get('/foreigner-registration', 'KYC\KYCController@showForeignerSIMRegPage')->name('foreigner-sim.reg');
    Route::post('/foreigner-registration-save', 'KYC\KYCController@foreigner_register_new_MSISDN')->name('foreigner-sim.msisdn');

    Route::get('/foreigner-re-registration', 'KYC\KYCController@showForeignerReRegPage')->name('foreigner-sim.reg');
    Route::post('/foreigner-re-registration-save', 'KYC\KYCController@foreigner_re_register_MSISDN')->name('foreigner-sim.msisdn');

    Route::get('/check-registration', 'KYC\KYCController@showCheckSIMRegPage')->name('check-sim.reg');
    Route::post('/check-registration-post', 'KYC\KYCController@getSIMRegStatus')->name('check-sim.post');

    // Route::get('/user-registration', 'UserController@ShowCreateNewUser')->name('create-new.user');
    // Route::post('/user-registration-post', 'UserController@getSIMRegStatus')->name('check-sim.post');

    Route::get('/diplomat-registration', 'KYC\KYCController@ShowRegisterDiplomat')->name('create-new.user');
    Route::post('/diplomat-registration-post', 'KYC\KYCController@registerDiplomatSave')->name('check-sim.post');

    Route::get('/diplomat-registration-list', 'KYC\KYCController@ShowAllDiplomats')->name('create-new.user');
    //Route::post('/diplomat-registration-post', 'UserController@getSIMRegStatus')->name('check-sim.post');

    Route::get('/diplomat-registration-bulk', 'KYC\KYCController@showBulkDiplomatForm1')->name('register-diplomat-bulk.show');
    Route::get('/diplomat-registration-bulk2', 'KYC\KYCController@showBulkDiplomatForm2')->name('register-diplomat-bulk2.show');
    Route::post('/diplomat-registration-bulk-post1', 'KYC\KYCController@bulkDiplomatProcessPage1')->name('register-diplomat-bulk.post1');
    Route::post('/diplomat-registration-bulk-post2', 'KYC\KYCController@bulkDiplomatProcessPage2')->name('register-diplomat-bulk.post2');

    Route::get('/minor-registration', 'KYC\KYCController@ShowRegisterMinor')->name('minor-new.show');
    Route::post('/minor-registration-post1', 'KYC\KYCController@registerMinorSave_page1')->name('minor-new.post');
    Route::post('/minor-registration-post2', 'KYC\KYCController@registerMinorSave_page2')->name('minor-new.post');


    // Route::get('/de-registration', 'KYCController@showDeRegisterPage1')->name('de-register1.show');
    // Route::post('/de-registration-post1', 'KYCController@saveDeRegisterPage1')->name('de-register1.post');

    // Route::get('/de-registration-page-two', 'KYCController@showDeRegisterPage2')->name('de-register2.show');
    // Route::post('/de-registration-post2', 'KYCController@saveDeRegisterPage2')->name('de-register2.post');

    // Route::get('/de-registration-page-three', 'KYCController@showDeRegisterPage3')->name('de-register3.show');
    // Route::post('/de-registration-post3', 'KYCController@saveDeRegisterPage3')->name('de-register3.post');

    Route::post('/registration-total-mismatch', 'KYC\KYCController@registerTotalMismatch')->name('total-mismatch.post');

    Route::get('/defaced-new-registration', 'KYC\KYCController@getNewRegDefacedQuestion')->name('search.reg');
    Route::post('/defaced-new-reg-answer', 'KYC\KYCController@getNewRegDefacedAnswer')->name('search.msisdn.details');

    Route::get('/primary-sim-first', 'KYC\KYCController@showPrimarySIMFirstPage')->name('primary-msisdn.first');
    Route::post('/primary-sim-first-post', 'KYC\KYCController@postPrimarySIMFirstPage')->name('primary-msisdn.first.post');

    Route::get('/primary-sim-second', 'KYC\KYCController@showPrimarySIMSecondPage')->name('primary-msisdn.second');
    Route::post('/primary-sim-second-post', 'KYC\KYCController@postPrimarySIMSecondPage')->name('primary-msisdn.second.post');

    Route::get('/secondary-sim-first', 'KYC\KYCController@showSecondarySIMFirstPage')->name('secondary-msisdn.first');
    Route::post('/secondary-sim-first-post', 'KYC\KYCController@postSecondarySIMFirstPage')->name('secondary-msisdn.first.post');

    Route::get('/secondary-sim-second', 'KYC\KYCController@showSecondarySIMSecondPage')->name('secondary-msisdn.second');
    Route::post('/secondary-sim-second-post', 'KYC\KYCController@postSecondarySIMSecondPage')->name('secondary-msisdn.second.post');

    Route::get('/primary-sim/other/first', 'KYC\KYCController@viewPrimaryMsisdnOtherFirst')->name('primary-msisdn.other.first');
    Route::post('/primary-sim/other/first-post', 'KYC\KYCController@getListPrimaryMsisdnOther')->name('primary-msisdn.other.first.post');

    Route::get('/primary-sim/other/second', 'KYC\KYCController@viewPrimaryMsisdnOtherSecond')->name('primary-msisdn.other.second');
    Route::post('/primary-sim/other/second-post', 'KYC\KYCController@setPrimaryMsisdnOther')->name('primary-msisdn.other.post');

    Route::get('/secondary-sim/other/first', 'KYC\KYCController@viewSecondaryMsisdnOtherFirst')->name('secondary-msisdn.other.first');
    Route::post('/secondary-sim/other/first-post', 'KYC\KYCController@getListSecondaryMsisdnOther')->name('secondary-msisdn.other.first.post');

    Route::get('/secondary-sim/other/second', 'KYC\KYCController@viewSecondaryMsisdnOtherSecond')->name('secondary-msisdn.other.second');
    Route::post('/secondary-sim/other/second-post', 'KYC\KYCController@setSecondaryMsisdnOther')->name('secondary-msisdn.other.post');


    /*
    /------------------------------
    BEGIN DE-REG ROUTES
    /------------------------------
    */
    Route::get('/de-registration/nida', 'KYC\RegistrationController@deRegNidaPage')->name('dereg.nida');
    Route::get('/de-registration/msisdn', 'KYC\RegistrationController@deRegMsisdnPage')->name('dereg.msisdn');
    Route::get('/de-registration/code', 'KYC\RegistrationController@deRegCodePage')->name('dereg.code');

    /*
    /------------------------------
    BEGIN ONE-SIM ROUTES
    /------------------------------
    */

    Route::get('/one-sim/new-reg', 'KYC\RegistrationController@viewOneSIMStart')->name('one-sim.register');
    //Route::post('/one-sim/new-reg-post', 'RegistrationController@postOneSIMStart')->name('one-sim.register.post');

    Route::get('/one-sim/new-reg/primary', 'KYC\RegistrationController@viewOneSIMRegisterPrimary')->name('one-sim.register.primary');
    //Route::post('/one-sim/new-reg-primary-post', 'RegistrationController@postOneSIMRegisterPrimary')->name('one-sim.register.primary.post');

    Route::get('/one-sim/new-reg/secondary', 'KYC\RegistrationController@viewOneSIMRegisterSecondary')->name('one-sim.register.secondary');
    //Route::post('/one-sim/new-reg-secondary-post', 'RegistrationController@postOneSIMRegisterSecondary')->name('one-sim.register.secondary.post');

    Route::get('/one-sim/diplomat/new-reg', 'KYC\RegistrationController@diplomatStartPage')->name('one-sim.register.diplomat');
    //Route::post('/one-sim/diplomat/new-reg-post', 'RegistrationController@postOneSIMDiplomatStart')->name('one-sim.register.diplomat.post');

    Route::get('/one-sim/diplomat/register-primary', 'KYC\RegistrationController@diplomatRegisterPrimaryPage')->name('one-sim.register.diplomat.primary');
    // Route::post('/one-sim/diplomat/new-reg-primary-post', 'RegistrationController@postDiplomatRegisterPrimary')->name('one-sim.register.diplomat.primary.post');

    Route::get('/one-sim/diplomat/register-secondary', 'KYC\RegistrationController@diplomatRegisterSecondaryPage')->name('one-sim.register.diplomat.secondary');
    //Route::post('/one-sim/diplomat/new-reg-secondary-post', 'RegistrationController@postDiplomatRegisterSecondary')->name('one-sim.register.diplomat.secondary.post');

    Route::get('/one-sim/visitor/new-reg', 'KYC\RegistrationController@viewVisitorStart')->name('one-sim.register.visitor');
    //Route::post('/one-sim/visitor/new-reg-post', 'RegistrationController@postVisitorStart')->name('one-sim.register.visitor.post');

    Route::get('/one-sim/visitor/primary', 'KYC\RegistrationController@viewVisitorRegisterPrimary')->name('one-sim.register.visitor.primary');
    //Route::post('/one-sim/visitor/new-reg-primary-post', 'RegistrationController@postVisitorRegisterPrimary')->name('one-sim.register.visitor.primary.post');

    Route::get('/one-sim/visitor/secondary', 'KYC\RegistrationController@viewVisitorRegisterSecondary')->name('one-sim.register.visitor.secondary');
    //Route::post('/one-sim/visitor/new-reg-secondary-post', 'RegistrationController@postVisitorRegisterSecondary')->name('one-sim.register.visitor.secondary.post');

    Route::get('/one-sim/bulk/new-reg', 'KYC\RegistrationController@viewBulkRegistrationStart')->name('one-sim.register.bulk');
    //Route::post('/one-sim/bulk/new-reg-post', 'Web\OneSIM\RegistrationController@postBulkRegistrationStart')->name('one-sim.register.bulk.post');

    Route::get('/one-sim/bulk/primary/spoc', 'KYC\RegistrationController@viewBulkRegistrationPrimarySPOC')->name('one-sim.register.bulk.primary-spoc');
    Route::get('/one-sim/bulk/primary/register', 'KYC\RegistrationController@viewBulkRegistrationPrimarySave')->name('one-sim.register.bulk.primary');

    Route::get('/one-sim/minor', 'KYC\RegistrationController@viewMinorRegistrationCheck')->name('one-sim.minor');
    Route::get('/one-sim/minor/register', 'KYC\RegistrationController@viewMinorRegistrationPrimary')->name('one-sim.minor.register');

    Route::get('/one-sim/primary/start', 'KYC\RegistrationController@setPrimaryStartPage')->name('one-sim.primary.start');
    Route::get('/one-sim/primary/set', 'KYC\RegistrationController@setPrimaryPage')->name('one-sim.primary.set');

    Route::get('/one-sim/secondary/start', 'KYC\RegistrationController@setSecondaryStartPage')->name('one-sim.secondary.start');
    Route::get('/one-sim/secondary/set', 'KYC\RegistrationController@setSecondaryPage')->name('one-sim.secondary.set');

    Route::get('/one-sim/bulk/secondary/spoc', 'KYC\RegistrationController@bulkRegistrationSecondarySPOCPage')->name('register.bulk.secondary.spoc');
    Route::get('/one-sim/bulk/secondary/register', 'KYC\RegistrationController@bulkRegistrationSecondaryCompanyPage')->name('register.bulk.secondary.company');

    Route::get('/one-sim/bulk-declaration/start', 'KYC\RegistrationController@bulkDeclarationStartPage')->name('declaration.bulk.start');
    Route::get('/one-sim/bulk-declaration/second', 'KYC\RegistrationController@bulkDeclarationSecondPage')->name('declaration.bulk.second');



    /*
    |---------------------------------------------------------------------------------
    | Begin KYA Reports routes
    |--------------------------------------------------------------------------------
    */
    Route::get('/reports/agents', 'Report\KYAReportController@index')->name('agents.list');
    Route::get('/reports/agents/zone/{Id}', 'Report\KYAReportController@getAgentsByZoneId')->name('agents.zone.list');
    Route::post('/reports/agents/zone', 'Report\KYAReportController@fetchAgentsByZoneId')->name('agents.zone.list.post');
    Route::post('/reports/agents', 'Report\KYAReportController@fetchAgentsByLocation')->name('agents.location.list.post');

    Route::get('/reports/agentstaff/Agent', 'Report\KYAReportController@viewStaffByAgentID')->name('staff.village');
    Route::post('/reports/agentstaff/Agent', 'Report\KYAReportController@staffByAgent')->name('agents.location.list.post');

    Route::get('/reports/agentstaff/verifiedIMS', 'Report\KYAReportController@viewStaffOnboardedIMS')->name('staff.village');

    Route::get('/reports/agentstaff/location', 'Report\KYAReportController@viewStaffByLocation')->name('staff.village');

    Route::post('/reports/agentstaff/location', 'AgentStaffController@getStaffByLocation')->name('agentstaff.device.clear');

    Route::post('/reports/agentstaff/location', 'Report\KYAReportController@getStaffByLocation')->name('agentstaff.device.clear');

    Route::get('/reports/agentstaff/registrations', 'Report\KYAReportController@viewStaffByregistrations')->name('staff.registrations');

    Route::get('/reports/kyc', 'Report\KYCReportController@viewRegJourney')->name('customer.journey');
    Route::post('/reports/customer-journey-download', 'Report\KYCReportController@filterReports')->name('customer.journey.download');

    Route::get('support/agent-staff-details', 'Support\KYASupportController@viewStaffAccountDetails')->name('customer.journey');
    Route::post('/support/post-agent-staff-details', 'Support\KYASupportController@getStaffAccountDetails')->name('customer.journey.download');

    Route::get('support/customer-reg-details', 'Support\KYCSupportController@viewCustomerRegDetails')->name('customer.journey');
    Route::post('/support/post-customer-reg-details', 'Support\KYCSupportController@getCustomerRegDetails')->name('customer.journey.download');

    Route::get('support/user-details', 'Support\KYASupportController@viewUserDetails')->name('user.details');
    Route::post('/support/post-user-details', 'Support\KYASupportController@getUserDetails')->name('customer.journey.download');

    Route::get('support/user-manage/block', 'Support\KYASupportController@viewUserBlock')->name('user.details');
    Route::post('/support/post-user-block', 'Support\KYASupportController@blockUser')->name('customer.journey.download');

    Route::get('support/user-manage/unblock', 'Support\KYASupportController@viewUserUnblock')->name('user.details');
    Route::post('/support/post-user-unblock', 'Support\KYASupportController@unblockUser')->name('customer.journey.download');

    Route::get('support/view-staff-id', 'Support\KYASupportController@viewAgentStaffID')->name('user.details');

    Route::get('support/view-staff-id-pdf', 'Support\KYASupportController@viewAgentStaffIDPDF')->name('user.details');

    Route::get('support/download/staff-id-pdf', 'Support\KYASupportController@downloadAgentStaffIDPDF')->name('user.details');

    Route::get('support/customer-reg-details/id', 'Support\KYCSupportController@regDetailsPerID')->name('registration.details.id');

    Route::get('support/alternative-visitors', 'Support\KYCSupportController@allVisitorAlternative')->name('all.alternative.visitors');
    Route::get('support/alternative-visitors/review', 'Support\KYCSupportController@singleVisitorAlternative')->name('single.alternative.visitors');

    /*
    |---------------------------------------------------------------------------------
    | Begin Roles routes
    |--------------------------------------------------------------------------------
    */
    Route::get('/permissions/roles', 'User\RoleManagementController@index')->name('roles.management');

    Route::get('/permissions/user/rights', 'User\RoleManagementController@getUserRights')->name('user.rights');

    Route::get('/permissions/user/roles', 'User\RoleManagementController@getUserRoles')->name('user.roles');

    Route::get('/permissions/user/rights/{Id}', 'User\RoleManagementController@getUserRightbyRoles')->name('user.roles');

    Route::post('/permissions/user/rights', 'User\RoleManagementController@saveRoleRights')->name('agents.location.list.post');

    Route::get('/permissions/users', 'User\UserManagementController@index')->name('user.management');

    Route::post('/permissions/user', 'User\UserManagementController@saveUserManagement')->name('agents.location.list.post');

    Route::get('/list-users', 'User\UserManagementController@ShowCreateNewUser')->name('list.users');
    Route::post('/create-user-post', 'User\UserManagementController@CreateNewUser');
});
