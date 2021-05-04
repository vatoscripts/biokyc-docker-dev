$(document).ready(function() {
    $("#registrationCategory").change(function() {
        $("#TIN-file").val("");
        $("#TIN").val("");

        $("#business-licence-file").val("");
        $("#business-licence").val("");

        $("#BRELA-file").val("");
        $("#company-email").val("");

        $("#spoc-attachment-file").val("");

        $("#TIN-file").prop("disabled", false);
        $("#TIN").attr("readOnly", false);

        $("#business-licence-file").prop("disabled", false);
        $("#business-licence").attr("readOnly", false);

        $("#BRELA-file").prop("disabled", false);
        $("#company-email").attr("readOnly", false);

        $("#spoc-attachment-file").prop("disabled", false);

        var regCat = $("#registrationCategory").val();
        var isM2M = $("#machine2machine").val();

        // if (isM2M == 'Y') {

        // }

        if (regCat == "COMP") {
            $("#spoc-attachment-file").prop("disabled", true);
        }

        if (regCat == "INST") {
            $("#TIN-file").prop("disabled", true);
            $("#TIN").attr("readOnly", true);

            $("#business-licence-file").prop("disabled", true);
            $("#business-licence").attr("readOnly", true);

            $("#BRELA-file").prop("disabled", true);
        }

        if (regCat == "CEMP") {
            $("#spoc-attachment-file").aprop("disabled", true);

            $("#company-email").attr("readOnly", true);
        }
    });
});

document.querySelector("#bulkRegNIDA").addEventListener("click", function(e) {
    e.preventDefault();

    $("#bulkRegNIDAForm").addClass("whirl traditional");

    $(".form-erros").html("");
    $("#error-message").html("");

    $("#fingerData").val(CapturedData);
    $("#fingerCode").val(CapturedFinger);

    $.ajax({
        url: "/bulk-registration-NIDA",
        type: "POST",
        data: $("#bulkRegNIDAForm").serialize(),
        success: function(success) {
            console.log(success);
            $("#bulkRegNIDAForm").removeClass("whirl traditional");
            $(".form-erros").html("");
            $("#bulk-register-page1")
                .modal()
                .fadeOut("fast");

            $("#bulk-register-page2").modal("show");
        },
        error: function(err) {
            $("#bulkRegNIDAForm").removeClass("whirl traditional");

            console.log(err);
            if (err.status == 422) {
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
            } else if (err.status == 413) {
                var d = document.getElementById("error-message");
                d.className +=
                    "text-center text-danger rounded-lg p-1 mt-1 lead mb-1";
                d.innerHTML += err.statusText;
            } else if (err.status == 0) {
                var d = document.getElementById("error-message");
                d.className +=
                    "text-center text-danger rounded-lg p-1 mt-1 lead mb-1";
                d.innerHTML += "Something went wrong. Please start afresh !";
            } else {
                var d = document.getElementById("error-message");
                d.className +=
                    "text-center text-danger rounded-lg p-1 mt-1 lead mb-1";
                d.innerHTML += err.responseJSON.message;
            }
        }
    });
});

var uploadForm = $("#bulkRegSaveForm");

uploadForm.submit(function(e) {
    //.addEventListener("click", function(e) {
    e.preventDefault();

    $("#bulkRegSaveForm").addClass("whirl traditional");

    $(".form-erros").html("");
    $("#error-message2").html("");

    var formData = new FormData(uploadForm[0]);

    $.ajax({
        url: "/bulk-registration-save",
        type: "POST",
        contentType: false,
        processData: false,
        dataType: "json", // what to expect back from the PHP script
        cache: false,
        data: formData,

        success: function(data) {
            console.log(data);

            $("#bulkRegSaveForm").removeClass("whirl traditional");

            swal({
                title: "Registration Success",
                text: data.message,
                icon: "success",
                button: "OK"
            }).then(() => {
                location.reload();
            });
        },
        error: function(err) {
            $("#bulkRegSaveForm").removeClass("whirl traditional");
            ErrorMessage(err);
        }
    });
});

function ErrorMessage(err) {
    console.log(err);
    if (err.status == 422) {
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
    } else if (err.status == 413) {
        var d = document.getElementById("error-message2");
        d.className += "text-center text-danger rounded-lg p-1 mt-1 lead mb-1";
        d.innerHTML += err.statusText;
    } else if (err.status == 0) {
        var d = document.getElementById("error-message2");
        d.className += "text-center text-danger rounded-lg p-1 mt-1 lead mb-1";
        d.innerHTML += "Something went wrong. Please start afresh !";
    } else {
        var d = document.getElementById("error-message2");
        d.className += "text-center text-danger rounded-lg p-1 mt-1 lead mb-1";
        d.innerHTML += err.responseJSON.message;
    }
}

function getErrorNumbers(res) {
    var list = "<ul>";
    res.forEach((num, index) => {
        list = "<li> " + num.Msisdn + "</li>";
    });
    list += "</ul>";

    return list;
}

function getDistricts(e) {
    var regionID = $("#regionID").val();

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
        var el = document.getElementById("ward-dropdown");
        getVillage(el);
    });
}

function getVillage(e) {
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
    });
}
