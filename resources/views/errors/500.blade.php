@extends('layout.error')

@section('content')

    <div class="content-heading">
        <h3 class="lead">Internal Server Error</h3>
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
                            <div class="mb-3"><em class="fa fa-wrench fa-4x"></em></div>
                            <div class="text-bold  text-lg text-danger mb-3">500</div>
                            <p class="m-0 text-bold  text-md">OH NO! Something went wrong !</p>
                            <p class="h3">Don't worry, we're now checking this.</p>
                            <p class="h4">In the meantime, please try links below or come back in a moment</p>
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
