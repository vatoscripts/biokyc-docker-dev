<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="bulk-register-page1" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> BULK REGISTRATION - PAGE 1
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="error-message"></blockquote>

            <div id="AgentNIDA" class="modal-body p-3">
                <form method="post" action="{{ action('BulkRegController@processBulkRegistration_page1') }}" class="mb-3" id="bulkRegNIDAForm" novalidate>
                    @csrf
                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">SPOC MSISDN</label>
                            <input name="spocMsisdn" value="" type="text" class="form-control" id="spoc-msisdn" placeholder="Enter SPOC MSISDN e.g 255754xxxxxx">
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="text-bold" for="spocEmail">SPOC Email address</label>
                        <input name="spocEmail" type="email" class="form-control" id="spocEmail" aria-describedby="emailHelp" placeholder="Enter SPOC Email">
                    </div>

                    <div class="row">
                        <div class="form-group col-12">
                            <label class="text-bold">Region </label>
                            <select class="custom-select" id="regionID" name="region" onchange="getDistricts(this)">
                                <option value="">SELECT REGION</option>
                                @foreach ($regions as $item)
                                    <option value="{{$item['ID']}}">{{$item['Description']}}</option>
                                @endforeach
                            </select>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold">District</label>
                            <select name="district" class="form-control" onchange="getWards(this) "id="district-dropdown">
                            </select>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold">Ward</label>
                            <select class="form-control" name="ward" onchange="getVillage(this)" id="ward-dropdown"></select>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold">Street </label>
                            <select class="form-control" name="village"  id="village-dropdown"></select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="text-bold" for="exampleInputEmail1">NIDA Number</label>
                        <input id="NIN" name="NIN" class="form-control" type="text" placeholder="Enter NIDA number">
                    </div>

                    <input type="hidden" name="fingerData" id="fingerData">
                    <input type="hidden" name="fingerCode" id="fingerCode">
                    <div id="Div_fingerprint" style="margin-block-end: 10px;"></div>

                    <div class="modal-footer">
                        <button id="cancelNIDA" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="bulkRegNIDA" type="submit" class="btn btn-primary"> Proceed</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


