$(document).ready(function() {
    $(document).keypress(function(e) {
        if (e.which == 13) {
            // alert("enter key is pressed");
            e.preventDefault();
        }
    });
    //debugger;
    $("#checkMsisdnIcapBtn").click(function(e) {
        e.preventDefault();

        $(".form-erros").html("");
        $("#flash-message").html("");

        $("#checkMSISDNIcapForm").addClass("whirl traditional");

        $.ajax({
            url: "/recheck-msisdn",
            type: "POST",
            data: $("#checkMSISDNIcapForm").serialize(),
            success: function(success) {
                $("#checkMSISDNIcapForm").removeClass("whirl traditional");
                console.log(success);
                $("#foreigner-re-register").modal("show");
            },
            error: function(err) {
                $("#checkMSISDNIcapForm").removeClass("whirl traditional");
                //console.log(err);
                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    //console.log(err.responseJSON.errors);

                    // display errors on each form field
                    $.each(err.responseJSON.errors, function(i, error) {
                        var el = $(document).find(".input-group");
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
                    var d = document.getElementById("flash-message");
                    d.className =
                        " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                    d.innerHTML = err.responseJSON.message;
                }
            }
        });
    });

    document
        .querySelector("#ForeignerreregisterMSISDNBtn")
        .addEventListener("click", function(e) {
            e.preventDefault();

            $("#error-message").html("");
            $("<br>").remove();
            $(".form-erros").remove();

            $("#fingerData").val(CapturedData);
            $("#fingerCode").val(CapturedFinger);

            $("#ForeignerreregisterMSISDNForm").addClass("whirl traditional");

            $.ajax({
                url: "/foreigner-re-registration-save",
                type: "POST",
                data: $("#ForeignerreregisterMSISDNForm").serialize(),
                success: function(success) {
                    $("#ForeignerreregisterMSISDNForm").removeClass(
                        "whirl traditional"
                    );
                    console.log(success);
                    if (success.Code === 01) {
                        //alert("Failed");
                        swal({
                            title: "Failed",
                            text: success.message,
                            icon: "error",
                            button: "OK"
                        }).then(value => {
                            window.location = "/home";
                        });
                    } else if (success.Code === 00) {
                        //alert("Passed");
                        swal({
                            title: "Success",
                            text: success.message,
                            icon: "success",
                            button: "OK"
                        }).then(value => {
                            window.location = "/home";
                        });
                    } else if (success.OTP == true) {
                        $("#foreigner-re-register")
                            .modal()
                            .fadeOut("fast");
                        $("#total-mismatch-register").modal("show");
                    }
                },
                error: function(err) {
                    $("#ForeignerreregisterMSISDNForm").removeClass(
                        "whirl traditional"
                    );
                    if (err.status == 422) {
                        // when status code is 422, it's a validation issue
                        console.log(err.responseJSON);
                        // you can loop through the errors object and show it to the user
                        console.log(err.responseJSON.errors);
                        // display errors on each form field
                        $.each(err.responseJSON.errors, function(i, error) {
                            //var el = $(document).find(".input-group");
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
                        var d = document.getElementById("error-message");
                        d.className +=
                            "text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                        d.innerHTML += err.responseJSON.message;
                    }
                }
            });
        });
});

document
    .querySelector("#registerMismatchNBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("#error-message-ms").html("");
        $(".form-erros").remove();

        $("#registerMismatchForm").addClass("whirl traditional");

        $.ajax({
            url: "/registration-total-mismatch",
            type: "POST",
            data: $("#registerMismatchForm").serialize(),
            success: function(success) {
                console.log(success);
                $("#registerMismatchForm").removeClass("whirl traditional");

                if (success.code == 200) {
                    swal({
                        title: "Success !",
                        text: success.message,
                        icon: "success",
                        button: "OK"
                    }).then(value => {
                        window.location = "/home";
                    });
                } else if (success.code == 400) {
                    swal({
                        title: "Info !",
                        text: success.message,
                        icon: "info",
                        button: "OK"
                    }).then(value => {
                        window.location = "/home";
                    });
                }
            },
            error: function(err) {
                $("#registerMismatchForm").removeClass("whirl traditional");
                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    console.log(err.responseJSON.errors);
                    // display errors on each form field
                    $.each(err.responseJSON.errors, function(i, error) {
                        //var el = $(document).find(".input-group");
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
                    var d = document.getElementById("error-message-ms");
                    d.className +=
                        "text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                    d.innerHTML += err.responseJSON.message;
                }
            }
        });
    });
