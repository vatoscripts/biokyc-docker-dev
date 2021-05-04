$("#agentFrom-dropdown").empty();

var settingsFrom = {
    async: true,
    crossDomain: true,
    url: "/agents-list",
    method: "GET"
};

$.ajax(settingsFrom).done(function(response) {
    //console.log(response);
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

$(document).ready(function() {
    // $("#staffbyAgentTable").DataTable({
    //     dom: "Bfrtip",
    //     buttons: ["copy", "csv", "excel", "pdf", "print"]
    // });
});
