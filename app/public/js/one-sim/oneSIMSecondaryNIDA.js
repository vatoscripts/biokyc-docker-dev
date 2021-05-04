$(document).ready(function () {
    document
        .querySelector("#oneSIMSecondarySubmitNIDA")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("#flash-message").html("");
            $(".form-erros").html("");

            $("#fingerData").val(CapturedData);
            $("#fingerCode").val(CapturedFinger);

            $("#SecondarySIMNIDAForm").addClass("whirl traditional");

            $.ajax({
                url: "/secondary-sim-first-post",
                type: "POST",
                data: $("#SecondarySIMNIDAForm").serialize(),
                success: function (success) {
                    $("#SecondarySIMNIDAForm").removeClass("whirl traditional");

                    window.location = "/secondary-sim-second";
                },
                error: function (err) {
                    $("#SecondarySIMNIDAForm").removeClass("whirl traditional");

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
