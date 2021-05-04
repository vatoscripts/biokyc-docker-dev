document.querySelector("#agentsbyLocationWrapper").style.display = "none";

document
    .querySelector("#agentsByLocationBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();
        $("#agentsbyLocationReport").empty();
        document.querySelector("#agentsbyLocationWrapper").style.display =
            "none";
        $("#filterAgentLocation").addClass("whirl traditional");

        $.ajaxSetup({
            headers: {
                "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content")
            }
        });

        $.ajax({
            url: "/reports/agents",
            type: "POST",
            data: $("#agentsByLocation").serialize()
        })
            .done(function(agents) {
                $("#filterAgentLocation").removeClass("whirl traditional");
                //console.log(agents);
                document.querySelector(
                    "#agentsbyLocationWrapper"
                ).style.display = "block";
                $("#agentsbyLocationTable")
                    .find("tbody")
                    .empty();

                if (agents[1].length != 0) {
                    $("#agentsbyLocationTable").show();
                    for (var x = 0; x < agents[1].length; x++) {
                        var BusinessName = agents[1][x]["BusinessName"];
                        var ZoneName = agents[1][x]["ZoneName"];
                        var RegionName = agents[1][x]["RegionName"];
                        var ActiveYN = agents[1][x]["ActiveYN"];
                        var AgentID = agents[1][x]["AgentID"];
                        if (agents[1][x]["ActiveYN"] == "Y") {
                            ActiveYN =
                                '<div class="badge badge-success">Active</div>';
                        } else {
                            ActiveYN =
                                '<div class="badge badge-danger">Not Active</div>';
                        }
                        document.querySelector("#agentsCount").className = "";
                        $("#agentsCount").addClass("h4 text-info lead");
                        document.querySelector("#agentsCount").innerHTML =
                            "Found " + agents[1].length + " total Agent(s) !";
                        $("#agentsbyLocationTable")
                            .find("tbody")
                            .append(
                                '<tr class="gradeX"><td>' +
                                    BusinessName.toString() +
                                    '</td><td class="d-none d-sm-block">' +
                                    ZoneName.toString() +
                                    "</td><td>" +
                                    RegionName.toString() +
                                    "</td><td>" +
                                    ActiveYN +
                                    '</td><td><a href="/agent/' +
                                    AgentID.toString() +
                                    '" class="btn btn-square btn-info"><i class="fa fa-search mr-2"></i> View</a></td></tr>'
                            );
                    }
                    $("#agentsbyLocationTable").DataTable({
                        dom: "Bfrtip",
                        buttons: [
                            "copyHtml5",
                            "excelHtml5",
                            "csvHtml5",
                            "pdfHtml5"
                        ]
                    });
                } else {
                    this.className = "";
                    document.querySelector("#agentsCount").className = "";
                    $("#agentsbyLocationTable").hide();
                    $("#agentsCount").addClass("h4 text-danger lead");
                    document.querySelector("#agentsCount").innerHTML =
                        "Oops ! Looks like there are no any Agent(s) for the specified location.";
                }
            })
            .fail(function(err) {
                console.log(err);
            });
    });
