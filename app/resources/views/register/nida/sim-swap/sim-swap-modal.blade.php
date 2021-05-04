<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="sim-swap-register" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> CUSTOMER SIM SWAP
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="error-message"></blockquote>

            <div id="RegisterSIMSWAP" class="modal-body p-3">
                <form method="post" action="{{ action('KYC\KYCController@saveSIMSwapReg') }}" class="mb-3" id="SIMSwapregisterForm" novalidate>
                    @csrf
                    <div class="form-group">
                        <label class="text-bold" for="ICCID">ICCID Number</label>
                        <input id="ICCID" name="ICCID" class="form-control" type="text" placeholder="Enter ICCID number">
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
                        <button id="SIMSwapRegisterBtn" type="submit" class="btn btn-primary"> SWAP</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


