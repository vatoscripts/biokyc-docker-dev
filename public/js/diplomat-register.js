// document
//     .querySelector("#RegisterDiplomatBtn")
//     .addEventListener("click", function(e) {

$(document).ready(function() {
    var uploadForm = $("#registerDiplomatForm");

    uploadForm.submit(function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");

        var formData = new FormData(uploadForm[0]);

        $("#registerDiplomatForm").addClass("whirl traditional");

        $.ajax({
            url: "/diplomat-registration-post",
            type: "POST",
            contentType: false,
            processData: false,
            dataType: "json", // what to expect back from the PHP script
            cache: false,
            data: formData,
            success: function(data) {
                console.log(data);
                $("#registerDiplomatForm").removeClass("whirl traditional");

                swal({
                    title: "Success !",
                    text: data.message,
                    icon: "success",
                    button: "OK"
                }).then(value => {
                    window.location = "/home";
                });
            },
            error: function(err) {
                $("#registerDiplomatForm").removeClass("whirl traditional");

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

    document
        .querySelector("#clearFormBtn")
        .addEventListener("click", function() {
            document.getElementById("registerDiplomatForm").reset();
        });
});
