document
    .querySelector("#searchMsisdnDetailsBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");
        $("#customer-details").html("");

        $("#agent-staff-unblock").addClass("whirl traditional");

        $.ajax({
            url: "/search-registration",
            type: "POST",
            data: $("#searchMsisdnDetailsForm").serialize(),
            success: function(customer) {
                console.log(customer);
                // $('#AgentNIDA').removeClass('whirl traditional');
                $("#searchMsisdnDetailsForm").removeClass("whirl traditional");

                var client = customer.customer;

                //console.log(client.constructor === Object);

                if (client.constructor === Object) {
                    if (client.Surname !== null && client.FirstName !== null) {
                        var html =
                            '<div class="col-5"> <div class="card"> <div class="card-body"> <div class="row align-items-center"> <div class="col-5 text-center"><img class="img-thumbnail rounded-circle thumb196" src="data:image/png;base64, %Photo%" alt="Image"></div> <div class="col-7"> <div class="d-flex"> <div class="text-left"> <h3 class="mt-0">%fullName%</h3> <p class="text-muted"> <em class="fa-4x icon-check mr-2 text-success"></em> </p> </div> </div> </div> </div> </div> </div> </div> <div class="col-7"> <div class="card"> <div class="card-body"> <div class="row"> <div class="col-6"> <div class="row mb-2"> <div class="col-6 text-bold">MSISDN : </div> <div class="col-6"> %msisdn% </div> </div> <div class="row mb-2"> <div class="col-6 text-bold">REGISTRATION DATE: </div> <div class="col-6"> %regDate%</div> </div> <div class="row mb-2"> <div class="col-6 text-bold">GENDER : </div> <div class="col-6"> %gender% </div> </div> <div class="row mb-2"> <div class="col-6 text-bold">DOB : </div> <div class="col-6"> %dob% </div> </div> </div> <div class="col-6"> <div class="row mb-2"> <div class="col-6 text-bold">NATIONALITY : </div> <div class="col-6"> %nationality% </div> </div> <div class="row mb-2"> <div class="col-6 text-bold">ID TYPE : </div> <div class="col-6"> %IDtype%</div> </div> <div class="row mb-2"> <div class="col-5 text-bold">ID NUMBER : </div> <div class="col-7"> %IDnumber% </div> </div> <div class="row mb-2"> <div class="col-6 text-bold">AGENT : </div> <div class="col-6"> <a href="staff/%staffID%"> %agentName%</a></div> </div> </div> </div> </div> </div> </div>';
                        var newHtml = html.replace(
                            "%fullName%",
                            client.FirstName + " " + client.Surname
                        );

                        var dob = new Date(client.Dob);
                        var regDate = new Date(client.RegDate);

                        newHtml = newHtml.replace("%Photo%", client.Photo);

                        newHtml = newHtml.replace("%msisdn%", client.Msisdn);

                        newHtml = newHtml.replace(
                            "%regDate%",
                            regDate
                            //dateFormat(regDate, "mmmm dS, yyyy")
                        );
                        newHtml = newHtml.replace("%gender%", client.Sex);
                        newHtml = newHtml.replace(
                            "%nationality%",
                            client.Nationality
                        );
                        newHtml = newHtml.replace("%IDtype%", client.IDType);
                        newHtml = newHtml.replace("%msisndn%", client.Msisdn);
                        newHtml = newHtml.replace(
                            "%dob%",
                            dob
                            // /dateFormat(dob, "mm dS, yyyy")
                        );
                        newHtml = newHtml.replace(
                            "%agentName%",
                            client.AgentName
                        );
                        newHtml = newHtml.replace(
                            "%IDnumber%",
                            client.IDNumber
                        );
                        newHtml = newHtml.replace("%staffID%", client.AgentID);

                        document
                            .querySelector("#customer-details")
                            .insertAdjacentHTML("beforeend", newHtml);
                    } else {
                        var d = document.getElementById("flash-message");
                        d.className =
                            " text-center text-danger rounded-lg p-1 mt-1 font-weight-bold mb-1";
                        d.innerHTML = "Not Found";
                    }
                }
            },
            error: function(err) {
                $("#searchMsisdnDetailsForm").removeClass("whirl traditional");

                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    //console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    //console.log(err.responseJSON.errors);
                    // display errors on each form field
                    $.each(err.responseJSON.errors, function(i, error) {
                        var el = $(document).find(".input-group");

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
