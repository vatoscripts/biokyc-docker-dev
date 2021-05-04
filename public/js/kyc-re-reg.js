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
                $("#customer-reReg").modal("show");
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
        .querySelector("#reRegisterMSISDNBtn")
        .addEventListener("click", function(e) {
            e.preventDefault();

            $("#error-message").html("");

            $(".form-erros").html("");

            $("#fingerData").val(CapturedData);
            $("#fingerCode").val(CapturedFinger);

            $("#reRegisterMSISDNForm").addClass("whirl traditional");

            $.ajax({
                url: "/re-register-msisdn",
                type: "POST",
                data: $("#reRegisterMSISDNForm").serialize(),
                success: function(success) {
                    $("#reRegisterMSISDNForm").removeClass("whirl traditional");
                    console.log(success);
                    if (success.NIDACode == "172") {
                        $("#customer-reReg")
                            .modal()
                            .fadeOut("fast");

                        swal({
                            title: "Customer has defaced fingers",
                            text:
                                "Once accepted, customer will be required to answer personnal questions !",
                            icon: "warning",
                            buttons: true,
                            dangerMode: false
                        }).then(getQns => {
                            if (getQns) {
                                $("#defaced-customer-question")
                                    .modal("show")
                                    .fadeIn("slow");
                                getFirstQuestion();
                            } else {
                                window.location = "/home";
                            }
                        });
                    } else if (success.OTP == true) {
                        $("#customer-reReg")
                            .modal()
                            .fadeOut("fast");
                        $("#total-mismatch-register").modal("show");
                    } else {
                        swal({
                            title: "Success",
                            text: success.message,
                            icon: "success",
                            button: "OK"
                        }).then(() => {
                            location.reload();
                        });
                    }
                },
                error: function(err) {
                    $("#reRegisterMSISDNForm").removeClass("whirl traditional");

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

    function ErrorMessage(err) {
        if (err.status == 422) {
            // when status code is 422, it's a validation issue
            // console.log(err.responseJSON);
            // you can loop through the errors object and show it to the user
            // console.log(err.responseJSON.errors);
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
            //console.log(err.responseJSON.message);

            var d = document.getElementById("flash-message");
            d.className +=
                "text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
            d.innerHTML += err.responseJSON.message;
        }
    }
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
