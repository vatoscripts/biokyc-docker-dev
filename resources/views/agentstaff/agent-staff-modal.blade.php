<!---Place for device register modal-->
    <div class="modal fade" data-keyboard="false" data-backdrop="static" id="agent_register" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header alert-danger" style="height:40px;"> ONBOARD NEW AGENT STAFF
                    <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
                </div>

                <blockquote id="flash-message" class="p-2 text text-danger h5 ml-3"></blockquote>

                <div id="AgentStaffNIDA" class="modal-body p-3">
                    <form method="post" action="{{ action('KYA\AgentStaffController@createAgentStaffDB') }}" class="mb-3" id="sendNIDAForm" novalidate>
                        @csrf
						<input type="hidden" name="user" id="userRole" value="{{$user}}">	
                        <div class="form-group">
                            <label class="text-bold" for="exampleInputEmail1">Mobile Number</label>
                            <input name="mobile-phone" type="text" class="form-control" placeholder="Enter Mobile Number starting with 255..." required>
                        </div>

                        <div class="form-group">
                            <label class="text-bold" for="blockReason">Choose Shop/ServiceDesk Name</label>
                            <select class="custom-select" id="shopName-select" name="shopName"></select>
                        </div>

                        <div class="form-group">
                            <label class="text-bold" for="exampleInputEmail1">NIDA Number</label>
                            <input id="NIN" name="NIN" class="form-control" type="text" placeholder="Enter NIDA number" required>
                        </div>

                        <input type="hidden" name="fingerData" id="fingerData">
                        <input type="hidden" name="fingerCode" id="fingerCode">
                        <div id="Div_fingerprint" style="margin-block-end: 10px;"></div>

                        <div class="modal-footer">
                            <button id="cancelNIDA" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                            <button id="sendAgentStaffNIDA" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Onboard</button>
                        </div>

                    </form>
                </div>

            </div>
        </div>
    </div>
    <!----end device register modal-->

