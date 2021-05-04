document.querySelector("#agent-staff-migration-list-wrapper").style.display =
    "none";

$(document).ready(function() {
    $("#agentFrom-dropdown").empty();

    var settingsFrom = {
        async: true,
        crossDomain: true,
        url: "/agents-list",
        method: "GET"
    };

    $.ajax(settingsFrom).done(function(response) {
        //console.log(response);
        $("#agentFrom-dropdown").append(
            '<option value="" selected disabled hidden>Select Agent</option>'
        );
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["UserID"];
            var Data = response[x]["BusinessName"];
            var AgentUID = response[x]["UserID"];
            $("#agentFrom-dropdown").append(
                //'<option value="' + ID.toString() + '">' + Data + "</option>"
                '<option value="' +
                    ID.toString() +
                    '" name="' +
                    AgentUID.toString() +
                    '">' +
                    Data +
                    "</option>"
            );
        }
    });

    //var el = document.getElementById("agentFrom-dropdown");
    //getAgents(el);
});

function getAgents() {
    $("#agentTo-dropdown").empty();
    var el = document.getElementById("agentFrom-dropdown");

    //$('#agent-staff-migration-list').empty();
    document.querySelector(
        "#agent-staff-migration-list-wrapper"
    ).style.display = "none";

    var settingsTo = {
        async: true,
        crossDomain: true,
        url: "/agents-list",
        method: "GET"
    };

    $.ajax(settingsTo).done(function(responseTo) {
        for (x = 0; x < responseTo.length; x++) {
            var ID = responseTo[x]["UserID"];
            var Data = responseTo[x]["BusinessName"];
            var AgentUID = responseTo[x]["UserID"];
            //console.log(e.value.toString());
            if (ID == el.value.toString()) {
                //console.log(x,el);
                continue;
            }
            $("#agentTo-dropdown").append(
                '<option value="' +
                    ID.toString() +
                    '" name="' +
                    AgentUID.toString() +
                    '">' +
                    Data +
                    "</option>"
            );
        }
    });
}

var staff = new Array();

document.querySelector("#agentFromBtn").addEventListener("click", function(e) {
    e.preventDefault();
    var el = document.getElementById("agentFrom-dropdown");
    $("#agentFromBtn").attr("disabled", "disabled");

    var settings = {
        async: true,
        crossDomain: true,
        url: "/getStaffByAgent/" + el.value.toString(),
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        $("#agentFromBtn").removeAttr("disabled");
        $("#agent-staff-migration-list").empty();
        document.querySelector(
            "#agent-staff-migration-list-wrapper"
        ).style.display = "block";
        if (response.length != 0) {
            for (x = 0; x < response.length; x++) {
                var fullName =
                    response[x]["FirstName"] + " " + response[x]["Surname"];
                var Data = response[x]["BusinessName"];
                var ID = response[x]["AgentStaffID"];
                var status = response[x]["ActiveYN"];
                var Onboarded = response[x]["OnboardedToImsYN"];
                $("#agent-staff-migration-list").append(
                    '<span class="col-4"><input id="staff-checkboxes" type="radio" name="staff[]" value="' +
                        ID.toString() +
                        '"> <label>' +
                        fullName.toString() +
                        "</label> </span>"
                );
            }
        } else {
            document.querySelector("#agent-staff-migration-list").innerHTML =
                '<h4 class="text-danger lead">No Staff available for the Agent !</h4>';
        }
    });
});
