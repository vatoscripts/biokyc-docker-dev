<!DOCTYPE html>
<html lang="en">

<head>
    @include('includes.registration.head')
</head>

<body>
    <div class="wrapper">
        <!-- Top navbar-->
        <header class="topnavbar-wrapper">
            <!-- START Top Navbar-->
            @include('includes.registration.navbar')
        </header>
        <!-- END Top Navbar -->

        <!-- sidebar-->
        <aside class="aside-container">
            <!-- START Sidebar (left)-->
            <div class="aside-inner">
                @include('includes.registration.sidebar')
            </div>
            <!-- END Sidebar (left)-->
        </aside>

        <!-- Offsidebar -->
        <aside class="offsidebar d-none">
            <!-- START Off Sidebar (right)-->
            @include('includes.registration.offsidebar')
            <!-- End Off Sidebar (right)-->
        </aside>
        <!-- END Offsidebar -->

        <!-- Main section-->
        <section class="section-container">
            <!-- Page content-->
            <div class="content-wrapper">
                <div class="content-heading">
                    <div>
                        @yield('title')
                    </div>
                </div>
                <div class="">
                    @yield('content')
                </div>
            </div>
        </section>
        @include('includes.registration.footer')
    </div>
    @include('includes.registration.scripts')
    @include('includes.registration.register-modal')
</body>

</html>


