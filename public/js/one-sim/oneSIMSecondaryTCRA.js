$(document).ready(function () {
    document
        .querySelector("#oneSIMSecondarySubmitTCRA")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("#flash-message").html("");
            $(".form-erros").html("");

            $("#SecondarySIMTCRAForm").addClass("whirl traditional");

            $.ajax({
                url: "/secondary-sim-second-post",
                type: "POST",
                data: $("#SecondarySIMTCRAForm").serialize(),
                success: function (success) {
                    $("#SecondarySIMTCRAForm").removeClass("whirl traditional");

                    if (success.status == "150") {
                        swal({
                            title: "Success",
                            text: success.message,
                            icon: "success",
                            button: "OK",
                        }).then((value) => {
                            window.location = "/home";
                        });
                    } else {
                        swal({
                            title: "Error",
                            text: success.message,
                            icon: "error",
                            button: "OK",
                        }).then((value) => {
                            window.location = "/home";
                        });
                    }
                },
                error: function (err) {
                    $("#SecondarySIMTCRAForm").removeClass("whirl traditional");

                    if (err.status == 422) {
                        // display errors on each form field
                        $.each(err.responseJSON.errors, function (i, error) {
                            if (i == "secondaryMsisdn") {
                                var el = $(document).find(
                                    '[id="secondaryMSISDNList"]'
                                );

                                el.before(
                                    $(
                                        '<span class="form-erros mb-2" style="color: red;"><br/>' +
                                            error[0] +
                                            "</span>"
                                    )
                                );
                            } else {
                                var el = $(document).find('[name="' + i + '"]');
                                el.after(
                                    $(
                                        '<span class="form-erros mb-2" style="color: red;">' +
                                            error[0] +
                                            "</span>"
                                    )
                                );
                            }
                        });
                    } else {
                        var d = document.getElementById("error-message");
                        d.className =
                            " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                        d.innerHTML = err.responseJSON.message;
                    }
                },
            });
        });
});
