$(document).ready(function() {

document
    .querySelector("#searchStaffDetailsBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");
		document.querySelector("#customer-details").innerHTML = "";

        $("#searchStaffAccountDetailssForm").addClass("whirl traditional");

        $.ajax({
            url: "/support/post-agent-staff-details",
            type: "POST",
            data: $("#searchStaffAccountDetailssForm").serialize(),
            success: function(data) {
                console.log(data);
                $("#searchStaffAccountDetailssForm").removeClass(
                    "whirl traditional"
                );

                var client = data[0];

                //console.log(client.constructor === Object);

                if (data.length !== 0) {
                    if (client.constructor === Object) {
                        var html =
                            '<div class="col-12"><div class="card"><div class="card-body"><div class="row lead"><div class="col-6"><div class="row mb-2"><div class="col-6 text-monospace">USERNAME :</div><div class="col-6"> %username%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ACCOUNT STATUS:</div><div class="col-6"> %accountStatus%</div></div><div class="row mb-2"><div class="col-6 text-monospace">LOCKED STATUS :</div><div class="col-6"> %lockedStatus%</div></div><div class="row mb-2"><div class="col-6 text-monospace">LAST LOGIN DATE :</div><div class="col-6"> %lastLoginDate%</div></div><div class="row mb-2"><div class="col-6 text-monospace">MSISDN :</div><div class="col-6"> %msisdn%</div></div><div class="row mb-2"><div class="col-6 text-monospace">LAST OTP :</div><div class="col-6"> %otp%</div></div><div class="row mb-2"><div class="col-6 text-monospace">OTP CREATED TIME :</div><div class="col-6"> %otpCreatedTime%</div></div><div class="row mb-2"><div class="col-6 text-monospace">LOGIN STATUS :</div><div class="col-6"> %loginStatus%</div></div></div></div><div class="row lead"><div class="col-6"><div class="row mb-2"><div class="col-6 text-monospace">CREATED DATE :</div><div class="col-6"> %createdDate%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ATTEMPTED LOCKED TIME :</div><div class="col-6"> %attemptLockedTime%</div></div><div class="row mb-2"><div class="col-6 text-monospace">AGENT CATEGORY :</div><div class="col-6"> %agentCategory%</div></div><div class="row mb-2"><div class="col-6 text-monospace">DEVICE ID :</div><div class="col-6"> %DeviceID%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ID NUMBER :</div><div class="col-6"> %IDNUMBER%</div></div><div class="row mb-2"><div class="col-6 text-monospace">AGENT NAME :</div><div class="col-6"> %agentName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">BUSINESS NAME :</div><div class="col-6"> %businessName%</div></div></div></div><div class="row lead"><div class="col-6"><div class="row mb-2"><div class="col-6 text-monospace">CREATED BY :</div><div class="col-6"> %createdBY%</div></div><div class="row mb-2"><div class="col-6 text-monospace">CATEGORY NAME :</div><div class="col-6"> %categoryName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">MODIFIED DATE :</div><div class="col-6"> %modifiedDate%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ONBOARD STATUS :</div><div class="col-6"> %onboardStatus%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ONBOARD DATE :</div><div class="col-6"> %onboardDate%</div></div><div class="row mb-2"><div class="col-6 text-monospace">PASSWORD STATUS :</div><div class="col-6"> %passwordStatus%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ROLE NAME :</div><div class="col-6"> %roleName%</div></div></div></div></div></div></div>';
                        var newHtml = html.replace(
                            "%username%",
                            client.Username
                        );

                        newHtml = newHtml.replace(
                            "%accountStatus%",
                            client.ACCOUNTSTATUS
                        );

                        newHtml = newHtml.replace(
                            "%lockedStatus%",
                            client.LOCKEDSTATUS
                        );

                        newHtml = newHtml.replace(
                            "%lastLoginDate%",
                            client.LastLogonDate
                        );

                        newHtml = newHtml.replace("%otp%", client.Otp);
                        newHtml = newHtml.replace(
                            "%otpCreatedTime%",
                            client.OtpCreatedTime
                        );

                        newHtml = newHtml.replace("%msisdn%", client.Msisdn);

                        newHtml = newHtml.replace(
                            "%loginStatus%",
                            client.LOGGINSTATUS
                        );
                        newHtml = newHtml.replace(
                            "%createdDate%",
                            client.CreatedTime
                        );

                        newHtml = newHtml.replace(
                            "%agentCategory%",
                            client.CategoryName
                        );
                        newHtml = newHtml.replace(
                            "%DeviceID%",
                            client.DeviceID
                        );

                        newHtml = newHtml.replace(
                            "%IDNUMBER%",
                            client.IDNUMBER
                        );

                        newHtml = newHtml.replace(
                            "%agentName%",
                            client.AGENTNAME
                        );
                        newHtml = newHtml.replace(
                            "%businessName%",
                            client.BusinessName
                        );

                        newHtml = newHtml.replace(
                            "%createdBY%",
                            client.CREATEDBY
                        );
                        newHtml = newHtml.replace(
                            "%categoryName%",
                            client.CategoryName
                        );

                        newHtml = newHtml.replace(
                            "%lastLoginDate%",
                            client.LastLogonDate
                        );

                        newHtml = newHtml.replace(
                            "%modifiedDate%",
                            client.ModifiedDate
                        );
                        newHtml = newHtml.replace(
                            "%onboardStatus%",
                            client.ONBOARDSTATUS
                        );

                        newHtml = newHtml.replace(
                            "%onboardDate%",
                            client.OnboardedDate
                        );

                        newHtml = newHtml.replace(
                            "%passwordStatus%",
                            client.PasswordStatus
                        );
                        newHtml = newHtml.replace(
                            "%businessName%",
                            client.BusinessName
                        );

                        newHtml = newHtml.replace(
                            "%roleName%",
                            client.RoleName
                        );

                        newHtml = newHtml.replace(
                            "%attemptLockedTime%",
                            client.AttemptLockedTime
                        );

                        document
                            .querySelector("#customer-details")
                            .insertAdjacentHTML("beforeend", newHtml);
                    }
                } else {
                    var d = document.getElementById("flash-message");
                    d.className =
                        " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                    d.innerHTML = "Agent Staff Not Found !";
                }
            },
            error: function(err) {
                $("#searchStaffAccountDetailssForm").removeClass(
                    "whirl traditional"
                );
                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    console.warn(err.responseJSON.errors);
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
                    $("blockquote#flash-message").html(
                        "<li>" + err.responseJSON.message + "</li>"
                    );
                }
            }
        });
    });
});