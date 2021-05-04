function getFirstQuestion() {
    var settings = {
        async: false,
        crossDomain: true,
        url: "/defaced-new-registration",
        method: "GET"
    };

    $.ajax(settings)
        .done(function(response) {
            console.log(response);
            $("#QuestionCode").val(response["QuestionCode"]);

            if (response !== null && response["Ksw"]) {
                document
                    .querySelector("#defaced_qn")
                    .insertAdjacentHTML("afterbegin", response["Ksw"]);
            } else if (response["Result"]["ErrorCode"] == "051") {
                swal(
                    "Something went wrong while fetching questions from NIDA 051"
                );
            } else if (response["Result"]["ErrorCode"] == "171") {
                swal(
                    "Customer is NOT allowed to get Biometric Questions fron NIDA 171"
                );
            } else {
                swal("Something went wrong while fetching questions from NIDA");
            }
        })
        .fail(function(data) {
            ErrorMessage(data);
        });
}

document
    .querySelector("#defacedRegisterBtn")
    .addEventListener("click", function(e) {
        e.preventDefault();
        $("#defacedCustomerBlock").addClass("whirl traditional");
        getFirstAnswer();
    });

document.querySelector("#cancel").addEventListener("click", function(e) {
    e.preventDefault();
    //location.reload();
    console.log(e);
});

function getFirstAnswer() {
    var prevAnsw;
    $.ajax({
        url: "/defaced-new-reg-answer",
        type: "POST",
        data: $("#defacedCustomerForm").serialize(),
        success: function(success) {
            $("#defacedCustomerBlock").removeClass("whirl traditional");
            console.log(success);

            if (success.PrevAsw == "124") {
                prevAnsw = "Wrong";
            } else if (success.PrevAsw == "123") {
                prevAnsw = "Correct";
            }
            if (success.Result == null) {
                swal(`The answer is : ${prevAnsw} `).then(() => {
                    $("#defaced_qn").html("");
                    $("#QuestionCode").val(success["QuestionCode"]);
                    document
                        .querySelector("#defaced_qn")
                        .insertAdjacentHTML("afterbegin", success["Ksw"]);
                });
            } else if (
                typeof success.Result === "object" &&
                success.Result !== null &&
                success.Result.ErrorMessage == "Success" &&
                success.Result.ErrorCode == 0
            ) {
                swal({
                    title: "Registration Success",
                    text: "Registration completed successfully ",
                    icon: "success",
                    button: "OK"
                }).then(() => {
                    location.reload();
                });
            } else if (
                typeof success.Result === "object" &&
                success.Result !== null &&
                success.Result.ErrorCode == "122"
            ) {
                swal({
                    title: "NIDA Error",
                    text: "Something went wrong while contacting NIDA",
                    icon: "error",
                    button: "OK"
                }).then(() => {
                    location.reload();
                });
            } else if (
                typeof success.Result === "object" &&
                success.Result !== null &&
                success.Result.ErrorCode == 130
            ) {
                swal({
                    title: "Verification Failure",
                    text: "You have answered all the questions incorrectly",
                    icon: "error",
                    button: "OK"
                }).then(() => {
                    location.reload();
                });
            }
        },
        error: function(err) {
            $("#defacedCustomerBlock").removeClass("whirl traditional");

            ErrorMessage(err);
        }
    });
}
