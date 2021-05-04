@extends('layout.error')

@section('content')

    <div class="content-heading">
        <h3 class="lead">Page Not Found</h3>
    </div>

    @include('layout.flash-messages')

    <!-- START cards box-->
        <!-- END cards box-->
        <div class="row">
            <!-- START dashboard main content-->
            <div class="col-xl-12">
                <!-- START chart-->
                <!-- Button trigger modal -->

                <div class="">
                    <div class="">
                        <!-- START card-->
                        <div class="text-center mb-4">
                            <div class="mb-3"><em class="fa fa-exclamation-triangle fa-4x"></em></div>
                            <div class="text-lg h3 text-danger mb-3">404</div>
                            <p class="lead m-0 text-bold">We couldn't find this page.</p>
                            <p>The page you are looking for does not exists.</p>
                        </div>
                        <h3 class="text-center mb-4">
                            <a class="text-muted" href="{{ route('home') }}">Go to Dashboard</a>
                        </h3>
                    </div>
                </div>

            </div>
            <!-- END dashboard main content-->
        </div>

@endsection

