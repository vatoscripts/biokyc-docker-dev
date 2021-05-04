<!DOCTYPE html>
<html lang="en">

<head>
    @include('includes.auth.head')
</head>

<body class="layout-h">
    <div class="wrapper">
        <section id="app" class="section-container">
            <div class="content-wrapper">
                @yield('content')
            </div>
        </section>

        <footer class="row">
            @include('includes.auth.footer')
        </footer>
    </div>

</body>

</html>
