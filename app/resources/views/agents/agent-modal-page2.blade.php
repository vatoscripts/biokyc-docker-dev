<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="agent-register-page2" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> ONBOARD NEW AGENT/TEAM LEADER - PAGE 2
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

            <div id="AgentSave" class="modal-body p-3">

                    <form id="SaveAgentForm" method="post" action="{{ action('KYA\AgentsController@createAgentDB') }}" class="mb-3" enctype="multipart/form-data" novalidate>
                    @csrf
                    <div class="row">
                        <div class="col-xs-12 col-md-12">
                            <div class="form-group">
                                <label class="text-bold" for="exampleInputEmail1">Mobile Number</label>
                                <input name="mobile-phone" type="text" class="form-control" placeholder="Enter Mobile Number strating with 255...">
                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-5 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Business TIN Number</label>
                            <input name="TIN" type="text" class="form-control" id="validationTooltip01" placeholder="TIN" value="" required>
                        </div>
                        <div class="col-md-7 col-xs-12 mb-3">
                            <div class="custom-file">
                                <label class="text-bold" for="exampleInputEmail1">Upload a Valid TIN file in PDF format</label>
                                <input type="file" class="form-control-file" name="TIN-file" id="customFile" aria-describedby="TINfileHelp">

                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-5 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Business Licence Number</label>
                            <input name="business-licence" type="text" class="form-control" id="validationTooltip01" placeholder="Business Licence No" value="" required>
                        </div>
                        <div class="col-md-7 col-xs-12 mb-3">
                            <div class="custom-file">
                                <label class="text-bold" for="exampleInputEmail1">Upload a Valid Business Licence file in PDF format</label>
                                <input type="file" class="form-control-file" name="business-licence-file" id="business-licence-file" aria-describedby="LicencefileHelp">

                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Business Name</label>
                            <input name="business-name" type="text" class="form-control" id="validationTooltip01" placeholder="Company/Business Name" value="" required>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Business Category</label>
                            <select class="form-control" name="agent-category"  id="agent-category-dropdown"></select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="text-bold" for="exampleInputEmail1">Email address</label>
                        <input name="email" type="email" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" placeholder="Enter email">
                    </div>
                    <div class="form-group">
                        <label class="text-bold" for="exampleInputEmail1">Telephone Number</label>
                        <input name="business-phone" type="email" class="form-control" id="exampleInputEmail1" aria-describedby="emailHelp" placeholder="Phone Number">
                    </div>

                    <!--Material textarea-->
                    <div class="form-group">
                        <label class="text-bold" for="form7">Address Location</label>
                        <textarea name="business-location" id="form7" class="md-textarea form-control" rows="3"></textarea>
                    </div>

                    <div class="modal-footer">
                        <button id="cancelSaveAgent" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="SaveAgentBtn" type="submit" class="btn btn-primary">Onboard Agent</button>
                    </div>

                </form>


            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


