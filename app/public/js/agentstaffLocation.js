document.querySelector("#agentsbyLocationWrapper").style.display = "none";

$(document).ready(function() {
    $("#region-dropdown").empty();

    var settingsFrom = {
        async: true,
        crossDomain: true,
        url: "/staff-regions",
        method: "GET"
    };

    $.ajax(settingsFrom).done(function(response) {
        $("#region-dropdown").append(
            '<option value="" selected disabled hidden>Choose Region</option>'
        );
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#region-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
                //'<option value="' + ID.toString() + '" name="' + ID.toString() + '">' + Data + "</option>"
            );
        }
    });

    var el = document.getElementById("region-dropdown");

    getdistrict(el);
});

function getdistrict(e) {
    $("#district-dropdown").empty();
    var regionID = $("#region-dropdown").val();

    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-district/" + regionID,
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        $("#district-dropdown").append(
            '<option value="" selected disabled hidden>Choose District</option>'
        );
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            // console.log([ID, Data]);
            $("#district-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }

        var el = document.getElementById("district-dropdown");

        getWards(el);
    });
}

function getWards(e) {
    $("#ward-dropdown").empty();

    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-ward/" + e.value.toString(),
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        $("#ward-dropdown").append(
            '<option value="" selected disabled hidden>Choose Ward</option>'
        );
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#ward-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        //$("#ward-dropdown").val(currentregion);
        var el = document.getElementById("ward-dropdown");
        getVillage(el);
    });
}

function getVillage(e) {
    $("#village-dropdown").empty();
    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-village/" + e.value.toString(),
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        $("#village-dropdown").append(
            '<option value="" selected disabled hidden>Choose Ward</option>'
        );
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#village-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
    });
}

document
    .querySelector("#agentStaffByLocationBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();
        $("#agentsbyLocationReport").empty();
        document.querySelector("#agentsbyLocationWrapper").style.display =
            "none";
        $("#filterAgentLocation").addClass("whirl traditional");

        $.ajax({
            url: "/reports/agentstaff/location",
            type: "POST",
            data: $("#agentsByLocation").serialize()
        })
            .done(function(agentstaff) {
                $("#filterAgentLocation").removeClass("whirl traditional");
                //console.log(agentstaff.data);
                document.querySelector(
                    "#agentsbyLocationWrapper"
                ).style.display = "block";
                $("#agentstaffbyLocationTable")
                    .find("tbody")
                    .empty();

                if (agentstaff.data.length != 0) {
                    $("#agentstaffbyLocationTable").show();
                    for (var x = 0; x < agentstaff.data.length; x++) {
                        //console.log(agentstaff.length);
                        var fullName =
                            agentstaff.data[x]["FirstName"] +
                            " " +
                            agentstaff.data[x]["Surname"];
                        var businessName = agentstaff.data[x]["BusinessName"];
                        var regionName = agentstaff.data[x]["ImsRegion"];
                        var districtName = agentstaff.data[x]["ImsDistrict"];
                        var ActiveYN = agentstaff.data[x]["ActiveYN"];
                        var AgentID = agentstaff.data[x]["AgentStaffID"];
                        if (agentstaff.data[x]["ActiveYN"] == "Y") {
                            ActiveYN =
                                '<div class="badge badge-success">Active</div>';
                        } else {
                            ActiveYN =
                                '<div class="badge badge-danger">Not Active</div>';
                        }
                        document.querySelector("#agentsCount").className = "";
                        $("#agentsCount").addClass("h4 text-info lead");
                        document.querySelector("#agentsCount").innerHTML =
                            "Found " +
                            agentstaff.data.length +
                            " total Agent Staff !";
                        $("#agentstaffbyLocationTable")
                            .find("tbody")
                            .append(
                                '<tr class="gradeX"><td>' +
                                    fullName.toString() +
                                    '</td><td class="d-none d-sm-block">' +
                                    businessName.toString() +
                                    "</td><td>" +
                                    regionName.toString() +
                                    "</td><td>" +
                                    ActiveYN +
                                    '</td><td><a href="/agent/' +
                                    AgentID.toString() +
                                    '" class="btn btn-square btn-info"><i class="fa fa-search mr-2"></i> View</a></td></tr>'
                            );
                    }
                    $("#agentstaffbyLocationTable").DataTable({
                        dom: "Bfrtip",
                        buttons: ["csv", "excel", "pdf", "print"]
                    });
                } else {
                    this.className = "";
                    document.querySelector("#agentsCount").className = "";
                    $("#agentstaffbyLocationTable").hide();
                    $("#agentsCount").addClass("h4 text-danger lead");
                    document.querySelector("#agentsCount").innerHTML =
                        "Oops ! Looks like there are no any Agent(s) for the specified location.";
                }
            })
            .fail(function(err) {
                console.log(err);
            });
    });
