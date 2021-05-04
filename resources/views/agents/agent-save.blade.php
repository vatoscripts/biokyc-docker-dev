<script>
    $(document).ready(function(){

   $("#sendAgentNIDA").click(function(e){

    e.preventDefault();
     $.ajaxSetup({
          headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') }
      });

      $('.form-erros').html('');
      $("blockquote#flash-message").html("");

      $('#AgentNIDA').addClass('whirl traditional');

      var NIN = $("#NIN").val();
       $("#fingerData").val(CapturedData);
       $("#fingerCode").val(CapturedFinger);

      $.ajax({
        url: '/agents-nida',
        type: "POST",
        data: $('#sendNIDAForm').serialize(),
        success: function( success ) {
                    console.log(success);
                    $("#agent-register-page1").modal().fadeOut('slow');
                    $('#AgentNIDA').removeClass('whirl traditional');
                    $(".form-erros").html("");
                    $("#agent-register-page2").modal("show");
                    getAgentCategory();

        },
        error: function(err) {
                $('#AgentNIDA').removeClass('whirl traditional');
                $('#sendAgentStaffNIDA').removeAttr('disabled');
                $('#cancelNIDA').removeAttr('disabled');

                if (err.status == 422) { // when status code is 422, it's a validation issue
                console.log(err.responseJSON);
                // you can loop through the errors object and show it to the user
                console.log(err.responseJSON.errors);
                // display errors on each form field
                $.each(err.responseJSON.errors, function (i, error) {
                var el = $(document).find('[name="'+i+'"]');

                el.before('').after($('<span class="form-erros" style="color: red;">'+error[0]+'</span>'));
                    });
                }else {
                    console.log(err)
                    $('blockquote#flash-message').html('<li>'+ err.responseJSON.message+'</li>' );
                }
        }
      });

    });

    });

    function getAgentCategory() {
        $("#agent-category-dropdown").empty();

        $("#agent-category-dropdown").append(
            '<option value="" selected disabled hidden>Select Agent Channel Type</option>'
        );

        var settings = {
            async: false,
            crossDomain: true,
            url: "/agent-category",
            method: "GET"
        };

        $.ajax(settings).done(function(response) {
            //console.log(response);
            for (x = 0; x < response.length; x++) {
                var ID = response[x]["CategoryID"];
                var Code = response[x]["CategoryCode"];
                var Data = response[x]["CategoryName"];
                $("#agent-category-dropdown").append(
                    '<option value="' + ID.toString() + '">' + Data + "</option>"
                );
            }
        });
    }

    var uploadForm = $("#SaveAgentForm");

    uploadForm.submit(function(e) {

    //$("#SaveAgentBtn").click(function(e){

e.preventDefault();
 $.ajaxSetup({
      headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') }
  });

  $('.form-erros').html('');
  $("blockquote#flash-message").html("");

  $('#AgentSave').addClass('whirl traditional');
  var formData = new FormData(uploadForm[0]);
        //console.log(formData);

  $.ajax({
    url: '/create-agent',
    type: "POST",
    contentType : false,
    processData : false,
    dataType: 'json', // what to expect back from the PHP script
	cache: false,
    //data: $('#SaveAgentForm').serialize(),
    data        : formData,
    success: function( success ) {
                console.log(success);
                $("#agent-register-page1").modal().fadeOut('slow');
                $('#AgentSave').removeClass('whirl traditional');
                swal({
                    title: "Good job!",
                    text: success.message,
                    icon: "success",
                    button: "OK",
                    className: "AgentStaffNIDA-sa"
                }).then(value => {
                    //swal('The returned value is: ${value}');
                    location.reload();
                });
    },
    error: function(err) {
            $('#AgentSave').removeClass('whirl traditional');

            if (err.status == 422) { // when status code is 422, it's a validation issue
            console.log(err.responseJSON);
            // you can loop through the errors object and show it to the user
            console.log(err.responseJSON.errors);
            // display errors on each form field
            $.each(err.responseJSON.errors, function (i, error) {
            var el = $(document).find('[name="'+i+'"]');

            el.before('').after($('<span class="form-erros" style="color: red;">'+error[0]+'</span>'));
                });
            }else {
                console.log(err)
                $('blockquote#flash-message').html('<li>'+ err.responseJSON.message+'</li>' );
            }
    }
  });

});



</script>

