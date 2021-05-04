$(document).ready(function() {
    var regionID = $("#regionID").val();
    console.log(regionID);

    //$("#district-dropdown").empty();
    $("#district-dropdown").html(
        "<option value=''>--select district--</option>"
    );
    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-district/" + regionID,
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        //console.log(response);
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

    $("#block-staff-link").click(function(e) {
        e.preventDefault();

        document.getElementById("blockReasonText").disabled = true;

        $("#agent-staff-block-modal").modal("show");

        document.getElementById("blockReason").onchange = function(e) {
            //console.log(this.value)
            if (this.value == "Others –(Specify)") {
                document.getElementById("blockReasonText").disabled = false;
            } else {
                document.getElementById("blockReasonText").disabled = true;
            }
        };
    });

    $("#blockStaffBtn").click(function(e) {
        e.preventDefault();

        $(".form-erros").html("");

        $("#agent-staff-block").addClass("whirl traditional");

        $.ajax({
            url: "/block-agentstaff",
            type: "POST",
            data: $("#agent-staff-block-form").serialize(),
            success: function(success) {
                console.log(success);
                // $('#AgentNIDA').removeClass('whirl traditional');
                $("#agent-staff-block").removeClass("whirl traditional");
                swal({
                    title: "Good job!",
                    text: "You have successfully blocked this staff !",
                    icon: "success",
                    button: "OK"
                }).then(value => {
                    location.reload();
                });
            },
            error: function(err) {
                $("#agent-staff-block").removeClass("whirl traditional");

                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    //console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    //console.log(err.responseJSON.errors);
                    // display errors on each form field
                    $.each(err.responseJSON.errors, function(i, error) {
                        var el = $(document).find('[name="' + i + '"]');

                        el.before("").after(
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

    $("#unblock-staff-link").click(function(e) {
        e.preventDefault();

        //document.getElementById("unblockstaffFile").disabled = true;

        $("#agent-staff-block-modal").modal("show");

        document.getElementById("unblockReason").onchange = function(e) {
            //console.log(this.value)
            if (this.value == "approved") {
                //document.getElementById("unblockstaffFile").disabled = false;
            } else {
                //document.getElementById("unblockstaffFile").disabled = true;
            }
        };
    });

    $("#unblockStaffBtn").click(function(e) {
        e.preventDefault();

        $.ajaxSetup({
            headers: {
                "X-CSRF-TOKEN": $('meta[name="csrf-token"]').attr("content")
            }
        });

        $(".form-erros").html("");

        $("#agent-staff-unblock").addClass("whirl traditional");

        $.ajax({
            url: "/unblock-agentstaff",
            type: "POST",
            data: $("#agent-staff-unblock-form").serialize(),
            success: function(success) {
                console.log(success);
                // $('#AgentNIDA').removeClass('whirl traditional');
                $("#AgentStaffNIDA").removeClass("whirl traditional");
                swal({
                    title: "Good job!",
                    text: "You have successfully unblocked this staff !",
                    icon: "success",
                    button: "OK"
                }).then(value => {
                    location.reload();
                });
            },
            error: function(err) {
                $("#agent-staff-unblock").removeClass("whirl traditional");

                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    //console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    //console.log(err.responseJSON.errors);
                    // display errors on each form field
                    $.each(err.responseJSON.errors, function(i, error) {
                        var el = $(document).find('[name="' + i + '"]');

                        el.before("").after(
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

function getWards(e) {
    //$("#ward-dropdown").empty();
    $("#ward-dropdown").html("<option value=''>--select ward--</option>");
    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-ward/" + e.value.toString(),
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
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
    //$("#village-dropdown").empty();
    $("#village-dropdown").html(
        "<option value=''>-- select village --</option>"
    );
    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-village/" + e.value.toString(),
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#village-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        //$("#ward-dropdown").val(currentregion);
        // var el = document.getElementById("village-dropdown");
        // getVillage(el);
    });
}
