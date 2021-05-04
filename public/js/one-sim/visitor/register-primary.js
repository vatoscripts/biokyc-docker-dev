$(document).ready(function () {
    document
        .querySelector("#registerNewPrimaryVisitorBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("#flash-message").html("");
            $(".form-erros").html("");

            $("#fingerData").val(CapturedData);
            $("#fingerCode").val(CapturedFinger);

            $("#registerNewPrimaryVisitorForm").addClass("whirl traditional");

            $.ajax({
                url: "/one-sim/visitor/new-reg-primary-post",
                type: "POST",
                data: $("#registerNewPrimaryVisitorForm").serialize(),
                success: function (success) {
                    $("#registerNewPrimaryVisitorForm").removeClass(
                        "whirl traditional"
                    );

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
                    $("#registerNewPrimaryVisitorForm").removeClass(
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
