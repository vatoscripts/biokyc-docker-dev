<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="description" content="">
<meta name="keywords" content="">
<meta name="csrf-token" content="{{ csrf_token() }}">
<link rel="icon" type="image/x-icon" href="{{ asset('favicon.ico') }}">
<title> @yield('title') | VTL BioKYC Portal </title>
<!-- SIMPLE LINE ICONS-->
<link href="{{ asset('css/simple-line-icons/css/simple-line-icons.css') }}" rel="stylesheet">
<!-- FONT AWESOME-->
<link href="{{ asset('css/fontawesome-free/css/brands.css') }}" rel="stylesheet">
<link href="{{ asset('css/fontawesome-free/css/regular.css') }}" rel="stylesheet">
<link href="{{ asset('css/fontawesome-free/css/solid.css') }}" rel="stylesheet">
<link href="{{ asset('css/fontawesome-free/css/fontawesome.css') }}" rel="stylesheet">
<!-- =============== BOOTSTRAP STYLES ===============-->
<link href="{{ asset('css/styles/bootstrap.css') }}" rel="stylesheet">
<link href="{{ asset('css/styles/dist/whirl.css') }}" rel="stylesheet">
<!-- =============== APP STYLES ===============-->
<link href="{{ asset('css/styles/app.css') }}" rel="stylesheet" id="maincss">
<link href="{{ asset('css/styles/theme-h.css') }}" rel="stylesheet">
<link href="{{ asset('css/styles/styles.css') }}" rel="stylesheet" id="basecss">

@yield('bio-background')

<script>
    function getfingurecapture(){
        alert(CapturedData);
        $("#fingerData").val(CapturedData);
        $("#fingerCode").val(CapturedFinger);
    }
</script>


