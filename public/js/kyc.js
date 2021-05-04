$(document).ready(function() {
    $(document).keypress(function(e) {
        if (e.which == 13) {
            // alert("enter key is pressed");
            e.preventDefault();
        }
    });

    $("#checkMsisdnIcapBtn").click(function(e) {
        e.preventDefault();

        $("#flash-message").html("");
        $(".form-erros").html("");

        $("#checkMSISDNIcapForm").addClass("whirl traditional");

        $.ajax({
            url: "/check-msisdn",
            type: "POST",
            data: $("#checkMSISDNIcapForm").serialize(),
            success: function(success) {
                $("#checkMSISDNIcapForm").removeClass("whirl traditional");
                console.log(success);
                $("#new-customer-register").modal("show");
            },
            error: function(err) {
                $("#checkMSISDNIcapForm").removeClass("whirl traditional");

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
});

document
    .querySelector("#registerNewMSISDNBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("#error-message").html("");
        $("<br>").remove();
        $(".form-erros").remove();

        $("#fingerData").val(CapturedData);
        $("#fingerCode").val(CapturedFinger);

        $("#registerNewMSISDNForm").addClass("whirl traditional");

        $.ajax({
            url: "/register-new-msisdn",
            type: "POST",
            data: $("#registerNewMSISDNForm").serialize(),
            success: function(success) {
                $("#registerNewMSISDNForm").removeClass("whirl traditional");
                console.log(success);

                if (success.NIDACode == "172") {
                    $("#new-customer-register")
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
                } else {
                    swal({
                        title: "Success",
                        text: success.message,
                        icon: "success",
                        button: "OK"
                    }).then(value => {
                        window.location = "/home";
                    });
                }
            },
            error: function(err) {
                $("#registerNewMSISDNForm").removeClass("whirl traditional");
                // $("#sendAgentStaffNIDA").removeAttr("disabled");
                //$("#cancelNIDA").removeAttr("disabled");
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
