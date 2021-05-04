document
    .querySelector("#checkMsisdnDetailsBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");
        $("#customer-details").html("");

        $("#checkMsisdnDetailsForm").addClass("whirl traditional");

        $.ajax({
            url: "/check-registration-post",
            type: "POST",
            data: $("#checkMsisdnDetailsForm").serialize(),
            success: function(customer) {
                console.log(customer);
                // $('#AgentNIDA').removeClass('whirl traditional');
                $("#checkMsisdnDetailsForm").removeClass("whirl traditional");

                // var client = customer.customer;

                //console.log(client.constructor === Object);

                if (customer.constructor === Object) {
                    if (customer.RegistrationStatus && customer.bioRegStatus) {
                        var html =
                            '<div class="col-8"><div class="card"><div class="card-body"><div class="row lead"><div class="col-12"><div class="row mb-2"><div class="col-4 text-bold">FULL NAME : </div><div class="col-8"> %fullName% </div></div><div class="row mb-2"><div class="col-4 text-bold">REGISTRATION STATUS: </div><div class="col-8"> %regStatus%</div></div><div class="row mb-2"><div class="col-4 text-bold">BIO-REG STATUS : </div><div class="col-8"> %bioregStatus% </div></div><div class="row mb-2"><div class="col-4 text-bold">DOB : </div><div class="col-8"> %dob% </div></div><div class="row mb-2"><div class="col-4 text-bold">ID NUMBER : </div><div class="col-8"> %IDnumber% </div></div><div class="row mb-2"><div class="col-4 text-bold">CODE : </div><div class="col-8"> %code% </div></div><div class="row mb-2"><div class="col-4 text-bold">MESSAGE : </div><div class="col-8"> %message% </div></div></div></div></div></div></div>';
                        var newHtml = html.replace(
                            "%fullName%",
                            customer.FirstName + " " + customer.LastName
                        );

                        newHtml = newHtml.replace(
                            "%regStatus%",
                            customer.RegistrationStatus
                        );
                        newHtml = newHtml.replace(
                            "%bioregStatus%",
                            customer.bioRegStatus
                        );

                        var dob = new Date(customer.Dob);

                        newHtml = newHtml.replace("%IDtype%", customer.IDType);

                        newHtml = newHtml.replace("%dob%", customer.Dob);
                        newHtml = newHtml.replace("%IDnumber%", customer.IDNo);
                        newHtml = newHtml.replace("%code%", customer.Code);
                        newHtml = newHtml.replace(
                            "%message%",
                            customer.Message
                        );

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
