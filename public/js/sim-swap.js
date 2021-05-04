$(document).ready(function() {

document
    .querySelector("#checkMsisdnIcapBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $(".form-erros").html("");
        $("#flash-message").html("");

        $("#checkMSISDNSIMSWAPForm").addClass("whirl traditional");

        $.ajax({
            url: "/sim-swap-msisdn",
            type: "POST",
            data: $("#checkMSISDNSIMSWAPForm").serialize(),
            success: function(success) {
                $("#checkMSISDNSIMSWAPForm").removeClass("whirl traditional");
                console.log(success);
                $("#sim-swap-register").modal("show");
            },
            error: function(err) {
                $("#checkMSISDNSIMSWAPForm").removeClass("whirl traditional");

                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    //console.log(err.responseJSON.errors);

                    // display errors on each form field
                    $.each(err.responseJSON.errors, function(i, error) {
                        var el = $(document).find(".input-group");
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
                    var d = document.getElementById("flash-message");
                    d.className =
                        "text-danger text-center rounded-lg p-1 mt-1 font-weight-bold mb-1";
                    d.innerHTML = err.responseJSON.message;
                }
            }
        });
    });

document
    .querySelector("#SIMSwapRegisterBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("#error-message").html("");

        $(".form-erros").html("");

        $("#fingerData").val(CapturedData);
        $("#fingerCode").val(CapturedFinger);

        $("#SIMSwapregisterForm").addClass("whirl traditional");

        $.ajax({
            url: "/sim-swap-save",
            type: "POST",
            data: $("#SIMSwapregisterForm").serialize(),
            success: function(success) {
                $("#SIMSwapregisterForm").removeClass("whirl traditional");
                console.log(success);

                swal({
                    title: "Success",
                    text: success.message,
                    icon: "success",
                    button: "OK"
                }).then(() => {
                    location.reload();
                });
            },
            error: function(err) {
                $("#SIMSwapregisterForm").removeClass("whirl traditional");

                ErrorMessage(err);
            }
        });
    });

function ErrorMessage(err) {
    if (err.status == 422) {
        // when status code is 422, it's a validation issue
        console.log(err.responseJSON);
        // you can loop through the errors object and show it to the user
        console.log(err.responseJSON.errors);
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
        var d = document.getElementById("error-message");
        d.className +=
            "text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
        d.innerHTML += err.responseJSON.message;
    }
}

});