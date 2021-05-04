$(document).ready(function() {
document
    .querySelector("#searchCutomerDetailsBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");
        document.querySelector("#customer-details").innerHTML = "";

        $("#searchStaffAccountDetailssForm").addClass("whirl traditional");

        $.ajax({
            url: "/support/post-customer-reg-details",
            type: "POST",
            data: $("#searchStaffAccountDetailssForm").serialize(),
            success: function(data) {
                console.log(data);
                $("#searchStaffAccountDetailssForm").removeClass(
                    "whirl traditional"
                );

                if (data.length !== 0) {
                    data.forEach(client => {
                        var html =
                            '<div class="col-8"><div class="card pl-4"><div class="card-body"><div class="row lead"><div class="col-6"><div class="row mb-2"><div class="col-6 text-monospace">REGISTRATION DATE :</div><div class="col-6"> %regDate%</div></div><div class="row mb-2"><div class="col-6 text-monospace">MSISDN :</div><div class="col-6"> %msisdn%</div></div><div class="row mb-2"><div class="col-6 text-monospace">CUSTOMER NAME :</div><div class="col-6"> %customerName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ID NUMBER :</div><div class="col-6"> %IDnumber%</div></div><div class="row mb-2"><div class="col-6 text-monospace">ID TYPE :</div><div class="col-6"> %IDtype%</div></div><div class="row mb-2"><div class="col-6 text-monospace">TYPE :</div><div class="col-6"> %type%</div></div><div class="row mb-2"><div class="col-6 text-monospace">STAFF AGENT MOBILE :</div><div class="col-6"> %agentMobile%</div></div><div class="row mb-2"><div class="col-6 text-monospace">STAFF AGENT NAME :</div><div class="col-6"> %agentName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">AGENT NAME :</div><div class="col-6"> %superAgentName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">AGENT PHONE :</div><div class="col-6"> %superAgentPhone%</div></div><div class="row mb-2"><div class="col-6 text-monospace">REGION NAME :</div><div class="col-6"> %regionName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">TERRITORY NAME :</div><div class="col-6"> %territoryName%</div></div><div class="row mb-2"><div class="col-6 text-monospace">DEVICE MODEL :</div><div class="col-6"> %deviceModel%</div></div><div class="row mb-2"><div class="col-6 text-monospace">REGISTRATION TYPE :</div><div class="col-6"> %regType%</div></div><div class="row mb-2"><div class="col-7 text-monospace">REGISTRATION CATEGORY :</div><div class="col-5"> %regCat%</div></div><div class="row mb-2"><div class="col-6 text-monospace">MISMATCH OTP :</div><div class="col-6"> %mismatchOTP%</div></div><div class="row mb-2"><div class="col-6 text-monospace">MISMATCH OTP TIME:</div><div class="col-6"> %mismatchOTPTime%</div></div><div class="row mb-2"><div class="col-6 text-monospace">CVM STATUS :</div><div class="col-6"> %cvmStatus%</div></div><div class="row mb-2"><div class="col-6 text-monospace">REGISTRATION STATUS :</div><div class="col-6"> %icapState%</div></div><div class="row mb-2"><div class="col-6 text-monospace">REASON:</div><div class="col-6"> %reason%</div></div></div></div></div></div></div>';
                        var newHtml = html.replace("%regDate%", client.REGDATE);
                        newHtml = newHtml.replace("%msisdn%", client.MSISDN);
                        newHtml = newHtml.replace(
                            "%customerName%",
                            client.CUSTOMERNAME
                        );
                        newHtml = newHtml.replace(
                            "%IDnumber%",
                            client.IDNUMBER
                        );
                        newHtml = newHtml.replace("%IDtype%", client.IDTYPE);
                        newHtml = newHtml.replace("%type%", client.Type);
                        newHtml = newHtml.replace(
                            "%agentMobile%",
                            client.AGENTMOBILE
                        );
                        newHtml = newHtml.replace(
                            "%agentName%",
                            client.AgentName
                        );
                        newHtml = newHtml.replace(
                            "%superAgentName%",
                            client.SUPERAGENTNAME
                        );
                        newHtml = newHtml.replace(
                            "%regionName%",
                            client.REGIONNAME
                        );
                        newHtml = newHtml.replace(
                            "%territoryName%",
                            client.TERRITORYNAME
                        );
                        newHtml = newHtml.replace(
                            "%deviceModel%",
                            client.DEVICEMODEL
                        );
                        newHtml = newHtml.replace("%regType%", client.REGTYPE);
                        newHtml = newHtml.replace(
                            "%icapState%",
                            client.ICAP_STATE
                        );
                        newHtml = newHtml.replace(
                            "%superAgentPhone%",
                            client.TEAMLEADERPHONE
                        );
                        newHtml = newHtml.replace(
                            "%regCat%",
                            client.RegCategory
                        );
                        newHtml = newHtml.replace(
                            "%mismatchOTP%",
                            client.MISMATCHOTP
                        );

                        newHtml = newHtml.replace(
                            "%mismatchOTPTime%",
                            client.OtpSentTime
                        );

                        newHtml = newHtml.replace(
                            "%cvmStatus%",
                            client.CVMStatus
                        );
                        newHtml = newHtml.replace("%reason%", client.REASON);
                        document
                            .querySelector("#customer-details")
                            .insertAdjacentHTML("beforeend", newHtml);
                    });
                } else {
                    var d = document.getElementById("flash-message");
                    d.className =
                        " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                    d.innerHTML = "Customer Not Found !";
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
                        //var el = $(document).find(".input-group");
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
});