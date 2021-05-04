$(document).ready(function () {
    document
        .querySelector("#unblockUserBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $(".form-erros").html("");

            $("#user-unblock-form").addClass("whirl traditional");

            $.ajax({
                url: "/support/post-user-unblock",
                type: "POST",
                data: $("#user-unblock-form").serialize(),
                success: function (success) {
                    $("#user-unblock-form").removeClass("whirl traditional");

                    swal({
                        title: "Success!",
                        text: "User successfully activated !",
                        icon: "success",
                        button: "OK",
                    }).then((value) => {
                        window.location = "/home";
                    });
                },
                error: function (err) {
                    $("#user-unblock-form").removeClass("whirl traditional");

                    if (err.status == 422) {
                        $.each(err.responseJSON.errors, function (i, error) {
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
                        $("blockquote#flash-message").html(
                            "<li>" + err.responseJSON.message + "</li>"
                        );
                    }
                },
            });
        });
});
