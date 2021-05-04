$(document).ready(function () {
    document
        .querySelector("#searchSecondaryMsisdnListBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("blockquote#flash-message").html("");
            $(".form-erros").html("");

            $("#searchSecondaryMsisdnListForm").addClass("whirl traditional");

            $.ajax({
                url: "/secondary-sim/other/first-post",
                type: "POST",
                data: $("#searchSecondaryMsisdnListForm").serialize(),
                success: function (data) {
                    console.log(data);

                    $("#searchSecondaryMsisdnListForm").removeClass(
                        "whirl traditional"
                    );

                    window.location = "/secondary-sim/other/second";
                },
                error: function (err) {
                    $("#searchSecondaryMsisdnListForm").removeClass(
                        "whirl traditional"
                    );
                    if (err.status == 422) {
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
