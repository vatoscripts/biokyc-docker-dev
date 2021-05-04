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
                $("#new-minor-register-page2").modal("show");
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
    .querySelector("#MinorregisterNewMSISDNBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("#error-message").html("");
        $("<br>").remove();
        $(".form-erros").remove();

        $("#fingerData").val(CapturedData);
        $("#fingerCode").val(CapturedFinger);

        $("#MinorregisterNewMSISDNForm").addClass("whirl traditional");

        $.ajax({
            url: "/minor-registration-post1",
            type: "POST",
            data: $("#MinorregisterNewMSISDNForm").serialize(),
            success: function(success) {
                console.log(success);
                $("#MinorregisterNewMSISDNForm").removeClass(
                    "whirl traditional"
                );

                // swal({
                //     title: "Success !",
                //     text: data.message,
                //     icon: "success",
                //     button: "OK"
                // }).then(value => {
                //     window.location = "/home";
                // });
            },
            error: function(err) {
                $("#MinorregisterNewMSISDNForm").removeClass(
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

var uploadForm = $("#MinorregisterNewMSISDNForm2");

uploadForm.submit(function(e) {
    e.preventDefault();

    $("blockquote#flash-message").html("");
    $(".form-erros").html("");

    var formData = new FormData(uploadForm[0]);

    $("#MinorregisterNewMSISDNForm2").addClass("whirl traditional");

    $.ajax({
        url: "/minor-registration-post2",
        type: "POST",
        contentType: false,
        processData: false,
        dataType: "json", // what to expect back from the PHP script
        cache: false,
        data: formData,
        success: function(data) {
            console.log(data);
            $("#MinorregisterNewMSISDNForm2").removeClass("whirl traditional");

            $("#new-minor-register-page2")
                .modal()
                .fadeOut("fast");

            $("#new-minor-register-page1").modal("show");
        },
        error: function(err) {
            $("#MinorregisterNewMSISDNForm2").removeClass("whirl traditional");

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
