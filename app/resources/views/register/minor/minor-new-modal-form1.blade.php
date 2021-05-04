<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="new-minor-register-page1" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> NEW MINOR REGISTRATION
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="error-message"></blockquote>

            <div id="MinorRegisterNewMSISDN" class="modal-body p-3">
                <form method="post" action="{{ action('KYCController@registerMinorSave_page1') }}" class="mb-3" id="MinorregisterNewMSISDNForm" novalidate>
                    @csrf
                    <div class="form-group">
                        <label class="text-bold" for="msisdn">Guardian Phone Number</label>
                        <input id="guardian-msisdn" name="guardian-msisdn" class="form-control" type="text" placeholder="Enter Parent/Guardian number">
                    </div>
                    <div class="row">
                        <div class="form-group col-12">
                            <label class="text-bold">Relationship to Minor </label>
                            <select class="custom-select" id="minor-relationship-select" name="minor-relationship">
                                <option value="">SELECT RELATIONSHIP</option>
                                <option value="SON">SON</option>
                                <option value="DAUGHTER">DAUGHTER</option>
                                <option value="NIECE">NIECE</option>
                                <option value="NEPHEW">NEPHEW</option>
                                <option value="GRANDSON">GRANDSON</option>
                                <option value="GRANDDAUGHTER">GRANDDAUGHTER</option>
                                <option value="SISTER">SISTER</option>
                                <option value="BROTHER">BROTHER</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="text-bold" for="msisdn">Guardian NIN</label>
                        <input id="guardian-NIN" name="guardian-NIN" class="form-control" type="text" placeholder="Enter Parent/Guardian NIDA ID number">
                    </div>
                    <input type="hidden" name="fingerData" id="fingerData">
                    <input type="hidden" name="fingerCode" id="fingerCode">
                    <div id="Div_fingerprint" style="margin-block-end: 10px;"></div>

                    <div class="modal-footer">
                        <button id="cancel" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="MinorregisterNewMSISDNBtn" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Register</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


