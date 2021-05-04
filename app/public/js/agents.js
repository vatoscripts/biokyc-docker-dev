var currentregion = 0;
var currentterritory = 0;

$(document).ready(function() {
    $("#zone-dropdown").empty();

    var settings = {
        async: true,
        crossDomain: true,
        url: "/zone",
        method: "GET",
        headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') }
    };

    $.ajax(settings).done(function(response) {
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#zone-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        // console.log(response);
        var el = document.getElementById("zone-dropdown");
        getregion(el);
    });
});

function getregion(e) {
    $("#region-dropdown").empty();
    var settings = {
        async: true,
        crossDomain: true,
        url: "/region/" + e.value.toString(),
        method: "GET",
        headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') }
    };

    $.ajax(settings).done(function(response) {
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#region-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        $("#region-dropdown").val(currentregion);
        var el = document.getElementById("region-dropdown");
        getterritory(el);
    });
}

function getterritory(e) {
    $("#territory-dropdown").empty();
    var settings = {
        async: true,
        crossDomain: true,
        url: "/territory/" + e.value.toString(),
        method: "GET",
        headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') }
    };

    $.ajax(settings).done(function(response) {
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#territory-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        $("#territory-dropdown").val(currentterritory);
    });
}

function getAgentAddress(zone, region, territoty) {
    currentregion = region;
    currentterritory = territoty;

    $("#zone-dropdown").empty();

    var settings = {
        async: true,
        crossDomain: true,
        url: "/zone",
        method: "GET",
        headers: {  'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')  }
    };

    $.ajax(settings).done(function(response) {
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#zone-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        $("#zone-dropdown").val(zone);
        var el = document.getElementById("zone-dropdown");
        getregion(el);
    });
}

function update_address() {
    var sendData = {
        TerritoryID: $("#territory-dropdown").val(),
        AgentID: $("#agent_Id").val()
    };

    $.ajax({
        url: "/AgentAddress",
        method: "POST",
        data: JSON.stringify(sendData),
        dataType: "json",
        headers: {  'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') },
        success: function(data) {
            console.log(data);
            swal({
                title: "Good job!",
                text: "You have successfully updated the profile  !",
                icon: "success",
                button: "OK"
            });
        },
        error: function(xhr, status, errThrown) {
            console.log(xhr);
            console.log(status);
            console.log(errThrown);
        }
    });
}
