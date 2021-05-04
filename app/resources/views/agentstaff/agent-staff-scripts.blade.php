<script>
    $(document).ready(function(){
    //getDistricts();

    $("#PostVerifyIMS").click(function(e){
        $('#flash-message').html('');
        e.preventDefault();
        $.ajaxSetup({
            headers: { 'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content') }
        });

      $('#PostVerifyIMS').attr('disabled','disabled');
      $('#cancelIMS').attr('disabled','disabled');
      $('#staffVerify').addClass('whirl traditional');

      $.ajax({
        url: '/staff-verify-ims' ,
        type: "POST",
        data: $('#staffVerify').serialize(),
        success: function( success )
            {
                console.log(success)
                $('#staffVerify').removeClass('whirl traditional');
                $("#staff_verify_modal").modal();
        },
        error: function( json )
            {
                $('#staffVerify').removeClass('whirl traditional');
                $('#PostVerifyIMS').removeAttr('disabled');
                $('#cancelIMS').removeAttr('disabled');
                console.log(json)
                if(json.status == 500) {
                    $('blockquote#flash-message').html('<li>Something went wrong. Please Try Again !</li>' );
                }else {
                   // $('blockquote#flash-message').html('<li>'+ json.responseJSON.message+'</li>' );
                }

            },
            done: function () {

            }
      });
    });

    });


</script>
