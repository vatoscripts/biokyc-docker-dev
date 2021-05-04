<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="staff_verify_modal" tabindex="-1">
    <div class="modal-dialog modal-md">
        <div class="modal-content">
            <div class="modal-header alert-danger"> <h4>ONBOARD NEW AGENT STAFF</h4>
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

            <div id="AgentStaffVerifyOnboard" class="modal-body p-3">

                @if (session::has('DeviceVerify'))

                    <form method="post" action="{{ action('AgentStaffController@onboardAgentIMS') }}" class="mb-3" id="staffOnboard" novalidate>
                        @csrf
                        <div class="form-row">
                            <div id="Modaltest"> </div>
                            <div class="col-md-12 col-xs-12 mb-3">

                                <input name="isShared" class="form-check-input" id="isShared[]" type="checkbox" value="true">
                                <label class="form-check-label"> Shared Device</label>
                            </div>
                        </div>

                        <!--START OF REGIONS-->
                        <input type="hidden" id="regionID" value="{{ session::get('regID')}}">
                        <div class="form-row">
                            <div class="col-md-12 col-xs-12 mb-3">
                                <select class="form-control" onchange="getWards(this)"id="district-dropdown">
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="col-md-12 col-xs-12 mb-3">
                                <select class="form-control" name="" onchange="getVillage(this)" id="ward-dropdown"></select>

                            </div>
                        </div>

                        <div class="form-row">
                            <div class="col-md-12 col-xs-12 mb-3">
                                <select class="form-control" name=""  id="village-dropdown"></select>
                            </div>
                        </div>

                        <div class="modal-footer">
                            <button id="cancelIMS" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                            <button id="OnboardIMS" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Onboard</button>
                        </div>

                    </form>
                @endif
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


