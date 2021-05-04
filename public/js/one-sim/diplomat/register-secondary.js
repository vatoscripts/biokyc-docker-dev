$(document).ready(function () {
    var uploadForm = $("#registerDiplomatSecondaryForm");

    uploadForm.submit(function (e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");

        var formData = new FormData(uploadForm[0]);

        $("#registerDiplomatSecondaryForm").addClass("whirl traditional");

        $.ajax({
            url: "/one-sim/diplomat/new-reg-secondary-post",
            type: "POST",
            contentType: false,
            processData: false,
            dataType: "json", // what to expect back from the PHP script
            cache: false,
            data: formData,
            success: function (data) {
                $("#registerDiplomatSecondaryForm").removeClass(
                    "whirl traditional"
                );

                swal({
                    title: "Success !",
                    text: data.message,
                    icon: "success",
                    button: "OK",
                }).then((value) => {
                    window.location = "/home";
                });
            },
            error: function (err) {
                $("#registerDiplomatSecondaryForm").removeClass(
                    "whirl traditional"
                );

                if (err.status == 422) {
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
                    $("blockquote#flash-message").html(
                        "<li>" + err.responseJSON.message + "</li>"
                    );
                }
            },
        });
    });
});
