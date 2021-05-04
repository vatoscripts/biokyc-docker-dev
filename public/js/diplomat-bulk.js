$(document).ready(function() {
    var uploadForm = $("#registerDiplomatBulkForm2");

    uploadForm.submit(function(e) {
        e.preventDefault();

        $("blockquote#flash-message").html("");
        $(".form-erros").html("");

        var formData = new FormData(uploadForm[0]);

        $("#registerDiplomatBulkForm2").addClass("whirl traditional");

        $.ajax({
            url: "/diplomat-registration-bulk-post2",
            type: "POST",
            contentType: false,
            processData: false,
            dataType: "json", // what to expect back from the PHP script
            cache: false,
            data: formData,
            success: function(data) {
                console.log(data);
                $("#registerDiplomatBulkForm2").removeClass(
                    "whirl traditional"
                );

                // swal({
                //     title: "Success !",
                //     text: data.message,
                //     icon: "success",
                //     button: "OK"
                // }).then(value => {
                //     window.location = "/home";
                // });
            },
            error: function(err) {
                console.log(err);
                $("#registerDiplomatBulkForm2").removeClass(
                    "whirl traditional"
                );

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

function getDistricts(e) {
    var regionID = $("#regionID").val();
    console.log(regionID);

    //$("#district-dropdown").empty();
    $("#district-dropdown").html(
        "<option value=''>--select district--</option>"
    );
    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-district/" + regionID,
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        //console.log(response);
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            // console.log([ID, Data]);
            $("#district-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }

        var el = document.getElementById("district-dropdown");

        getWards(el);
    });
}

function getWards(e) {
    //$("#ward-dropdown").empty();
    $("#ward-dropdown").html("<option value=''>--select ward--</option>");
    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-ward/" + e.value.toString(),
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#ward-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        //$("#ward-dropdown").val(currentregion);
        var el = document.getElementById("ward-dropdown");
        getVillage(el);
    });
}

function getVillage(e) {
    //$("#village-dropdown").empty();
    $("#village-dropdown").html(
        "<option value=''>-- select village --</option>"
    );
    var settings = {
        async: true,
        crossDomain: true,
        url: "/staff-village/" + e.value.toString(),
        method: "GET"
    };

    $.ajax(settings).done(function(response) {
        for (x = 0; x < response.length; x++) {
            var ID = response[x]["ID"];
            var Data = response[x]["Description"];
            $("#village-dropdown").append(
                '<option value="' + ID.toString() + '">' + Data + "</option>"
            );
        }
        //$("#ward-dropdown").val(currentregion);
        // var el = document.getElementById("village-dropdown");
        // getVillage(el);
    });
}
