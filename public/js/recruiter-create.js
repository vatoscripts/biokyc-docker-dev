$(document).ready(function() {
    $("#recruiterCreateBtn").click(function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");
        $("#RecruiterNIDA").addClass("whirl traditional");

        var NIN = $("#NIN").val();
        $("#fingerData").val(CapturedData);
        $("#fingerCode").val(CapturedFinger);

        $.ajax({
            url: "/create-staff-recruiter",
            type: "POST",
            data: $("#createRecruiterForm").serialize(),
            success: function(data) {
                console.log(data);
                $("#RecruiterNIDA").removeClass("whirl traditional");
                swal({
                    title: "Good job!",
                    text: data.message,
                    icon: "success",
                    button: "OK"
                }).then(value => {
                    location.reload();
                });
            },
            error: function(err) {
                $("#RecruiterNIDA").removeClass("whirl traditional");

                if (err.status == 422) {
                    // when status code is 422, it's a validation issue
                    console.log(err.responseJSON);
                    // you can loop through the errors object and show it to the user
                    console.warn(err.responseJSON.errors);
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
                    console.log(err);
                    $("blockquote#flash-message").html(
                        "<li>" + err.responseJSON.message + "</li>"
                    );
                }
            }
        });
    });
});


$("#shopName-select").empty();

	var settingsFrom = {
		async: true,
		crossDomain: true,
		url: "/agentByUserID",
		method: "GET"
	};

	$.ajax(settingsFrom).done(function(response) {
		console.log(response);

		var AgentID = response[0]["AgentID"];
		var CategoryID = response[0]["CategoryID"];

		console.log(response[0]["CategoryID"]);

		if (CategoryID == 4 || CategoryID == 5) {
			$("#domainYN").val("Y");
			$("#username").prop("disabled", false);
		} else {
			$("#domainYN").val("N");
			$("#username").prop("disabled", true);
		}

		var settingsFrom2 = {
			async: true,
			crossDomain: true,
			url: "/agentShops/" + AgentID.toString(),
			method: "GET"
		};

		$.ajax(settingsFrom2).done(function(response2) {
			console.log(response2);
			$("#shopName-select").append(
				'<option value="" selected disabled hidden>Choose Shop</option>'
			);
			for (x = 0; x < response2.length; x++) {
				var ID = response2[x]["ShopID"];
				var Data = response2[x]["ShopName"];
				$("#shopName-select").append(
					'<option value="' + ID.toString() + '">' + Data + "</option>"
					//'<option value="' + ID.toString() + '" name="' + ID.toString() + '">' + Data + "</option>"
				);
			}
		});
	});