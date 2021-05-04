$(document).ready(function() {
    $("#shopName-select").empty();

    var userRole = $("#userRole").val();

    if (userRole == 3) {
        ressolveAgent();
    } else if (userRole == 4) {
        ressolverecruiter();
    }

    $("#sendAgentStaffNIDA").click(function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");

        $("#AgentStaffNIDA").addClass("whirl traditional");

        var NIN = $("#NIN").val();
        $("#fingerData").val(CapturedData);
        $("#fingerCode").val(CapturedFinger);

        $.ajax({
            url: "/agentstaff-nida",
            type: "POST",
            data: $("#sendNIDAForm").serialize(),
            success: function(data) {
                console.log(data);
                $("#AgentStaffNIDA").removeClass("whirl traditional");
                swal({
                    title: "Good job!",
                    text: data.message,
                    icon: "success",
                    button: "OK",
                    className: "AgentStaffNIDA-sa"
                }).then(value => {
                    location.reload();
                });
            },
            error: function(err) {
                $("#AgentStaffNIDA").removeClass("whirl traditional");
                $("#sendAgentStaffNIDA").removeAttr("disabled");
                $("#cancelNIDA").removeAttr("disabled");

                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    console.warn(err.responseJSON.errors);
                    // display errors on each form field
                    $.each(err.responseJSON.errors, function(i, error) {
                        var el = $(document).find('[name="' + i + '"]');

                        el.after(
                            $(
                                '<span class="form-erros" style="color: red;">' +
                                    error[0] +
                                    "</span>"
                            )
                        );
                    });
                } else {
                    console.log(err);
                    $("blockquote#flash-message").html(
                        "<li>" + err.responseJSON.message + "</li>"
                    );
                }
            }
        });
    });
});

function ressolveAgent() {
    $("#shopName-select").prop("disabled", false);

    var settingsFrom = {
        async: true,
        crossDomain: true,
        url: "agentByUserID",
        method: "GET"
    };

    $.ajax(settingsFrom).done(function(response) {
        console.log(response);

        if (response.length > 0) {
            var AgentID = response[0]["AgentID"];

            var settingsFrom2 = {
                async: true,
                crossDomain: true,
                url: "agentShops/" + AgentID.toString(),
                method: "GET"
            };

            $.ajax(settingsFrom2).done(function(response2) {
                console.log(response2);
                $("#shopName-select").append(
                    '<option value="" selected disabled hidden>Choose Shop</option>'
                );
                for (x = 0; x < response2.length; x++) {
                    var ID = response2[x]["ShopID"];
                    var Data = response2[x]["ShopName"];
                    $("#shopName-select").append(
                        '<option value="' +
                            ID.toString() +
                            '">' +
                            Data +
                            "</option>"
                    );
                }
            });
        }
    });
}

function ressolverecruiter() {
    var settingsFrom = {
        async: true,
        crossDomain: true,
        url: "recruiterByUserID",
        method: "GET"
    };

    $.ajax(settingsFrom).done(function(response) {
        console.log(response);

        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ShopID"];
            var Data = response[x]["ShopName"];
            $("#shopName-select").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
    });
}
