$(document).ready(function () {
    document
        .querySelector("#OneSIMRegisterNewDiplomatBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("#flash-message").html("");
            $(".form-erros").html("");

            $("#OneSIMRegisterNewDiplomatForm").addClass("whirl traditional");

            $.ajax({
                url: "/one-sim/diplomat/new-reg-post",
                type: "POST",
                data: $("#OneSIMRegisterNewDiplomatForm").serialize(),
                success: function (success) {
                    $("#OneSIMRegisterNewDiplomatForm").removeClass(
                        "whirl traditional"
                    );

                    if (success.status == 1) {
                        window.location = "/one-sim/diplomat/new-reg/secondary";
                    } else if (success.status == 2) {
                        window.location = "/one-sim/diplomat/new-reg/primary";
                    }
                },
                error: function (err) {
                    $("#OneSIMRegisterNewDiplomatForm").removeClass(
                        "whirl traditional"
                    );

                    if (err.status == 422) {
                        // display errors on each form field
                        $.each(err.responseJSON.errors, function (i, error) {
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
                        var d = document.getElementById("error-message");
                        d.className =
                            " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                        d.innerHTML = err.responseJSON.message;
                    }
                },
            });
        });
});
