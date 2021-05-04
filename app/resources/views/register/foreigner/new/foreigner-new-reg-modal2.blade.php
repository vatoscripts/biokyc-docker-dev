<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="new-foreigner-register-page2" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> NEW FOREIGNER REGISTRATION - PAGE 2
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="error-message"></blockquote>

            <div id="RegisterNewMSISDN" class="modal-body p-3">
                <form method="post" action="{{ action('KYCController@foreigner_register_new_MSISDN') }}" class="mb-3" id="ForeignerregisterNewMSISDNForm" novalidate>
                    @csrf
                    <input type="hidden" name="fingerData" id="fingerData">
                    <input type="hidden" name="fingerCode" id="fingerCode">
                    <div id="Div_fingerprint" style="margin-block-end: 10px;"></div>

                    <div class="modal-footer">
                        <button id="cancel" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="ForeignerregisterNewMSISDNBtn" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Register</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


