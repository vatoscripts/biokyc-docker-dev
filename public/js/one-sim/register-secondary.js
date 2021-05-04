$(document).ready(function () {
    document
        .querySelector("#OneSIMRegisterSecondaryNIDASubmit")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("#flash-message").html("");
            $(".form-erros").html("");

            $("#fingerData").val(CapturedData);
            $("#fingerCode").val(CapturedFinger);

            $("#OneSIMRegisterSecondaryNIDAForm").addClass("whirl traditional");

            $.ajax({
                url: "/one-sim/new-reg-secondary-post",
                type: "POST",
                data: $("#OneSIMRegisterSecondaryNIDAForm").serialize(),
                success: function (success) {
                    $("#OneSIMRegisterSecondaryNIDAForm").removeClass(
                        "whirl traditional"
                    );
                    console.log(success);

                    swal({
                        title: "Success",
                        text: success.message,
                        icon: "success",
                        button: "OK",
                    }).then((value) => {
                        window.location = "/home";
                    });
                },
                error: function (err) {
                    $("#OneSIMRegisterSecondaryNIDAForm").removeClass(
                        "whirl traditional"
                    );

                    if (err.status == 422) {
                        // when status code is 422, it's a validation issue
                        console.log(err.responseJSON);
                        // you can loop through the errors object and show it to the user
                        console.log(err.responseJSON.errors);

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
                        console.log(err);
                        var d = document.getElementById("error-message");
                        d.className =
                            " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                        d.innerHTML = err.responseJSON.message;
                    }
                },
            });
        });
});
