<!DOCTYPE html>
<html lang="en">

<head>
    @include('includes.auth.head')
</head>

<body>
    <div id="app" class="wrapper">
        <div class="block-center mt-4 wd-xl">
            @yield('content')
        </div>
        <footer class="row">
            @include('includes.auth.footer')
        </footer>
    </div>

</body>

@include('includes.auth.scripts')

<script>
    $(initSweetAlert);

    function initSweetAlert() {

        var terms = "All that you transmit and/or access as well as " +
            "activity that you do in EKYC system,may be intercepted, monitored, " +
            "disclosed and / or recorded by the company,to ensure compliance with " +
            "Companys Information Security Policy VTL - ITB - POL - 008 and establish the existence of facts ";

        $('#swal-demo2').on('click', function(e) {
            e.preventDefault();
            swal("Login Service Agreement", "By clicking the CONTINUE button below you agree that you understand and accept the following:" + terms)
        });
    }
</script>

</html>
