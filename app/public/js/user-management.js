$(document).ready(function () {
    document
        .querySelector("#searchUserDetailsBtn")
        .addEventListener("click", function (e) {
            e.preventDefault();

            $("blockquote#flash-message").html("");
            $(".form-erros").html("");
            document.querySelector("#user-details").innerHTML = "";
            document.querySelector("#user-manage-btn").innerHTML = "";

            $("#searchUserDetailssForm").addClass("whirl traditional");

            $.ajax({
                url: "/support/post-user-details",
                type: "POST",
                data: $("#searchUserDetailssForm").serialize(),
                success: function (data) {
                    console.log(data);
                    $("#searchUserDetailssForm").removeClass(
                        "whirl traditional"
                    );

                    var client = data[0];

                    //console.log(client.constructor === Object);

                    if (data.length !== 0) {
                        if (client.constructor === Object) {
                            var html =
                                '<div class="col-12"><div class="card"><div class="card-body"><div class="row myLead"><div class="col-6"><div class="row mb-2"><div class="col-6 text-monospace">USERNAME :</div><div class="col-6"> %username%</div></div><div class="row mb-2"><div class="col-6 text-monospace">FULL NAME :</div><div class="col-6"> %fullName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ROLE:</div><div class="col-6"> %role%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ACCOUNT ACTIVE :</div><div class="col-6"> %lockedStatus%</div></div><div class="row mb-2"><div class="col-6 text-monospace">MSISDN :</div><div class="col-6"> %msisdn%</div></div></div></div></div></div></div>';
                            var newHtml = html.replace(
                                "%username%",
                                client.Username
                            );

                            newHtml = newHtml.replace(
                                "%fullName%",
                                client.FullName
                            );

                            newHtml = newHtml.replace("%role%", client.Role);

                            newHtml = newHtml.replace(
                                "%lockedStatus%",
                                client.ActiveYN
                            );

                            newHtml = newHtml.replace(
                                "%msisdn%",
                                client.Msisdn
                            );

                            document
                                .querySelector("#user-details")
                                .insertAdjacentHTML("beforeend", newHtml);

                            var btnHtml;

                            if (client.ActiveYN == "Y") {
                                btnHtml =
                                    '<a id="block-staff-link" href="/support/user-manage/block" class="ml-3 btn btn-lg btn-outline-danger text-bold"> Proceed to block</a>';
                            } else if (client.ActiveYN == "N") {
                                btnHtml =
                                    '<a id="unblock-staff-link" href="/support/user-manage/unblock" class="btn ml-3 btn-lg btn-outline-info text-bold"> Proceed to unblock</em></a>';
                            }

                            document
                                .querySelector("#user-manage-btn")
                                .insertAdjacentHTML("beforeend", btnHtml);
                        }
                    } else {
                        var d = document.getElementById("flash-message");
                        d.className =
                            " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                        d.innerHTML = "User not found !";
                    }
                },
                error: function (err) {
                    $("#searchUserDetailssForm").removeClass(
                        "whirl traditional"
                    );
                    if (err.status == 422) {
                        // when status code is 422, it's a validation issue
                        console.log(err.responseJSON);
                        // you can loop through the errors object and show it to the user
                        console.warn(err.responseJSON.errors);
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
