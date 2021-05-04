$("#createUserBtn").click(function(e) {
    e.preventDefault();

    $(".form-erros").html("");
    $("blockquote#flash-message").html("");

    $("#createUserForm").addClass("whirl traditional");

    $.ajax({
        url: "/create-user-post",
        type: "POST",
        data: $("#createUserForm").serialize(),
        success: function(data) {
            console.log(data);
            $("#createUserForm").removeClass("whirl traditional");

            swal({
                title: "Congratulations !",
                text: data.message,
                icon: "success",
                button: "OK"
            }).then(value => {
                window.location = "/home";
            });
        },
        error: function(err) {
            $("#createUserForm").removeClass("whirl traditional");
            if (err.status == 422) {
                // when status code is 422, it's a validation issue
                console.log(err.responseJSON);
                // you can loop through the errors object and show it to the user
                console.log(err.responseJSON.errors);
                // display errors on each form field
                $.each(err.responseJSON.errors, function(i, error) {
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
        }
    });
});
