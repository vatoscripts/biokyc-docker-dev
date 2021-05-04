$(document).ready(function () {
    document
        .querySelector("#searchPrimaryMsisdnListBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("blockquote#flash-message").html("");
            $(".form-erros").html("");

            $("#searchPrimaryMsisdnListForm").addClass("whirl traditional");

            $.ajax({
                url: "/primary-sim/other/first-post",
                type: "POST",
                data: $("#searchPrimaryMsisdnListForm").serialize(),
                success: function (data) {
                    $("#searchPrimaryMsisdnListForm").removeClass(
                        "whirl traditional"
                    );

                    window.location = "/primary-sim/other/second";
                },
                error: function (err) {
                    $("#searchPrimaryMsisdnListForm").removeClass(
                        "whirl traditional"
                    );
                    if (err.status == 422) {
                        // display errors on each form field
                        $.each(err.responseJSON.errors, function (i, error) {
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
                        var d = document.getElementById("flash-message");
                        d.className =
                            " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                        d.innerHTML = err.responseJSON.message;
                    }
                },
            });
        });
});
