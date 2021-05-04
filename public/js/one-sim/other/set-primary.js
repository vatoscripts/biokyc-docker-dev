$(document).ready(function () {
    document
        .querySelector("#setPrimaryMsisdnOtherBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("#flash-message").html("");
            $(".form-erros").html("");

            $("#setPrimaryMsisdnOtherForm").addClass("whirl traditional");

            $.ajax({
                url: "/primary-sim/other/second-post",
                type: "POST",
                data: $("#setPrimaryMsisdnOtherForm").serialize(),
                success: function (success) {
                    $("#setPrimaryMsisdnOtherForm").removeClass(
                        "whirl traditional"
                    );

                    if (success.status == "0") {
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
                    $("#setPrimaryMsisdnOtherForm").removeClass(
                        "whirl traditional"
                    );

                    if (err.status == 422) {
                        // display errors on each form field
                        $.each(err.responseJSON.errors, function (i, error) {
                            console.log(i);

                            if (i == "primaryMsisdn") {
                                var el = $(document).find(
                                    '[id="primaryMSISDNList"]'
                                );

                                el.before(
                                    $(
                                        '<span class="form-erros mb-2" style="color: red;"><br/>' +
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
