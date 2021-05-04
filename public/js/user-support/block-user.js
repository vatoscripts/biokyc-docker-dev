$(document).ready(function () {
    document.getElementById("blockReasonText").disabled = true;
    document.getElementById("blockReasonText").style.display = "none";

    document.getElementById("blockReason").onchange = function (e) {
        if (this.value == "Others –(Specify)") {
            document.getElementById("blockReasonText").disabled = false;
            document.getElementById("blockReasonText").style.display = "block";
        } else {
            document.getElementById("blockReasonText").disabled = true;
            document.getElementById("blockReasonText").style.display = "none";
        }
    };

    document
        .querySelector("#blockUserBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $(".form-erros").html("");

            $("#user-block-form").addClass("whirl traditional");

            $.ajax({
                url: "/support/post-user-block",
                type: "POST",
                data: $("#user-block-form").serialize(),
                success: function (success) {
                    $("#user-block-form").removeClass("whirl traditional");

                    swal({
                        title: "Success!",
                        text: "User successfully blocked !",
                        icon: "success",
                        button: "OK",
                    }).then((value) => {
                        window.location = "/home";
                    });
                },
                error: function (err) {
                    $("#user-block-form").removeClass("whirl traditional");

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
                        console.log(err);
                        $("blockquote#flash-message").html(
                            "<li>" + err.responseJSON.message + "</li>"
                        );
                    }
                },
            });
        });
});
