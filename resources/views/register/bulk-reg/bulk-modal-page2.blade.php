<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="bulk-register-page2" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> BULK REGISTRATION - PAGE 2 TEST
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="error-message2"></blockquote>

            <div id="AgentSave" class="modal-body p-3">

                    <form id="bulkRegSaveForm" method="post" action="{{ action('BulkRegController@processBulkRegistration_page2') }}" class="mb-3" enctype="multipart/form-data">
                    @csrf

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Company/Institution Name</label>
                            <input name="business-name" type="text" class="form-control" id="validationTooltip01" placeholder="Enter Company or Business Name">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-6 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Is Machine-to-Machine ? </label>
                            <select class="custom-select" id="machine2machine" name="machine2machine">
                                <option value=""> -- Choose One --</option>
                                <option value="Y">YES</option>
                                <option value="N">NO</option>
                            </select>
                        </div>

                        <div class="col-6">
                            <label class="text-bold" for="registrationCategory">Registration Category</label>
                            <select class="custom-select" id="registrationCategory" name="registrationCategory">
                                <option value=""> -- Choose One --</option>
                                <option value="COMP">Company SIM Card Registration</option>
                                <option value="INST">Institution SIM Card Registration</option>
                                <option value="CEMP">Machine SIM Card Registration</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="text-bold" for="exampleInputEmail1">Company/Institution Email address</label>
                        <input name="company-email" type="email" class="form-control" id="company-email" aria-describedby="emailHelp" placeholder="Enter email">
                    </div>

                    <div class="form-row">
                        <div class="col-md-7 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Institution Introduction Letter</label>
                            <div class="custom-file">
                                <input type="file" class="form-control-file" name="spoc-attachment-file" id="spoc-attachment-file" aria-describedby="TINfileHelp">
                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-2"><label class="text-bold" for="exampleInputEmail1">TIN</label></div>
                        <div class="col-md-5 col-xs-12 mb-3">
                            <input name="TIN" type="text" class="form-control" id="TIN" placeholder="TIN">
                        </div>
                        <div class="col-md-5 col-xs-12 mb-3">
                            <div class="custom-file">
                                <input type="file" class="form-control-file" name="TIN-file" id="TIN-file" aria-describedby="TINfileHelp">
                                {{-- <small id="TINfileHelp" class="form-text text-muted">Please upload a valid Certified copy of TIN</small> --}}
                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-2"><label class="text-bold" for="exampleInputEmail1">Business Licence</label></div>
                        <div class="col-md-5 col-xs-12 mb-3">
                            <input name="business-licence" type="text" class="form-control" id="business-licence" placeholder="Business Licence Number">
                        </div>
                        <div class="col-md-5 col-xs-12 mb-3">
                            <div class="custom-file">
                                <input type="file" class="form-control-file" name="business-licence-file" id="business-licence-file" aria-describedby="LicencefileHelp">
                                {{-- <small id="LicencefileHelp" class="form-text text-muted">Please upload a valid Certified copy of Business License</small> --}}
                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-7 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Certificate of Incorporation (BRELA)</label>
                            <div class="custom-file">
                                <input type="file" class="form-control-file" name="BRELA-file" id="BRELA-file" aria-describedby="LicencefileHelp">
                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-7 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">MSISDN Attachment (Maximum 300 msisdns) </label>
                            <div class="custom-file">
                                <input type="file" class="form-control-file" name="MSISDN-file" id="MSISDN-file" aria-describedby="LicencefileHelp">
                            </div>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button id="cancelSaveAgent" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="bulkRegSave" type="submit" class="btn btn-primary"> Register</button>
                    </div>

                </form>


            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


