<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="total-mismatch-register" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;">CUSTOMER REGISTRATION - MISMATCH
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="error-message-ms"></blockquote>

            <div id="RegisterMismatchMSISDN" class="modal-body p-3">
                <form method="post" action="{{ action('KYC\KYCController@registerTotalMismatch') }}" class="mb-3" id="registerMismatchForm" novalidate>
                    @csrf
                    <div class="form-group">
                        <label class="text-bold" for="OTP">OTP</label>
                        <input id="OTP" name="OTP" class="form-control" type="text" placeholder="Enter OTP here...">
                    </div>
                    <div class="modal-footer">
                        <button id="cancel" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="registerMismatchNBtn" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Register</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


