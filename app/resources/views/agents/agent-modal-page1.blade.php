<!---Place for device register modal-->
    <div class="modal fade" data-keyboard="false" data-backdrop="static" id="agent-register-page1" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header alert-danger" style="height:40px;"> ONBOARD NEW AGENT/TEAM LEADER - PAGE 1
                    <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
                </div>

                <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

                <div id="AgentNIDA" class="modal-body p-3">
                    <form method="post" action="{{ action('KYA\AgentsController@createAgentQueryNIDA') }}" class="mb-3" id="sendNIDAForm" novalidate>
                        @csrf
                        <div class="form-group">
                            <label for="exampleInputEmail1" class="text-bold">NIDA Number</label>
                            <input id="NIN" name="NIN" class="form-control" type="text" placeholder="Enter NIDA number">
                        </div>
                        <input type="hidden" name="fingerData" id="fingerData">
                        <input type="hidden" name="fingerCode" id="fingerCode">
                        <div id="Div_fingerprint" style="margin-block-end: 10px;"></div>

                        <div class="modal-footer">
                            <button id="cancelNIDA" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                            <button id="sendAgentNIDA" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Onboard</button>
                        </div>
                    </form>
                </div>

            </div>
        </div>
    </div>
    <!----end device register modal-->


