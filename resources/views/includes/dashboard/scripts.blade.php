<script src="{{ asset('js/sweetalert.min.js') }}" defer> </script>
<script src="{{ asset('js/jquery-3.4.1.min.js') }}"></script>
<script src="{{ asset('js/app.js') }}"></script>
<script src="{{ asset('js/vtlbio.js') }}"></script>

<script>
    function getfingurecapture(){
        alert(CapturedData);
        $("#fingerData").val(CapturedData);
        $("#fingerCode").val(CapturedFinger);
    }
</script>

