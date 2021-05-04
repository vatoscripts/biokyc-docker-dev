<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="agent-zone-modal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> AGENTS BY ZONE
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

            <div id="AgentZoneModalBlock" class="modal-body p-3">
                <form method="post" action="{{ action('Report\KYAReportController@fetchAgentsByZoneId') }}" class="mb-3" id="agentsByZone" novalidate>
                    @csrf

                    <!--START OF REGIONS-->
                    <input type="hidden" id="zoneID" name="zoneID" value="">

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <select name="agentZone" class="form-control" id="agent-zone-dropdown">
                            </select>
                        </div>
                    </div>

                    <button id="agentsByZoneBtn" type="submit" class="btn btn-lg btn-outline-danger  float-right text-bold"><span class="fa fa-save"></span> Onboard</button>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->
<script>
$('#agent-zone-modal').on('show.bs.modal' , function() {
    console.log("Hey");
    $("#zone-dropdown").empty();

    var settings = {
        async: true,
        crossDomain: true,
        url: "/zone",
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        //console.log(response);
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#agent-zone-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }

    });

});
</script>
