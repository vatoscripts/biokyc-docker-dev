<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="recruiter-register-create" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header alert-danger" style="height:40px;"> ONBOARD NEW RECRUITER
                    <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
                </div>

                <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

                <div id="RecruiterNIDA" class="modal-body p-3">
                    <form method="post" action="{{ action('KYA\RecruiterController@createStaffRecruiter') }}" class="mb-3" id="createRecruiterForm" novalidate>
                        @csrf
                        <input type="hidden" name="domainYN" id="domainYN">
                        <div class="form-group">
                            <label class="text-bold" for="msisdn">Phone Number</label>
                            <input id="msisdn" name="msisdn" class="form-control" type="text" placeholder="Enter Phone Number e.g 255...">
                        </div>

                        <div class="form-group">
                            <label class="text-bold" for="exampleInputEmail1">Domain Username</label>
                            <input id="username" name="domain-username" type="text" class="form-control" placeholder="Enter Domain Username">
                        </div>

                        <div class="form-group">
                            <label class="text-bold" for="blockReason">Choose Shop/ServiceDesk Name</label>
                            <select class="custom-select" id="shopName-select" name="shopName"></select>
                        </div>

                        <div class="form-group">
                            <label class="text-bold" for="NIN">NIDA Number</label>
                            <input id="NIN" name="NIN" class="form-control" type="text" placeholder="Enter NIDA number">
                        </div>
                        <input type="hidden" name="fingerData" id="fingerData">
                        <input type="hidden" name="fingerCode" id="fingerCode">
                        <div id="Div_fingerprint" style="margin-block-end: 10px;"></div>

                        <div class="modal-footer">
                            <button id="cancel" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                            <button id="recruiterCreateBtn" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Onboard</button>
                        </div>
                    </form>
                </div>

            </div>
        </div>
    </div>
    <!----end device register modal-->


