@extends('layout.app')

@section('content')
<section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">
            <div class="col-12">
                <!-- START card-->
                <div class="text-center mb-4">
                <div class="text-lg h3 text-danger mb-3">404</div>
                <p class="lead m-0">We couldn't find this page.</p>
                <p>The page you are looking for does not exists.</p>
                <h2>{{ $exception->getMessage() }}</h2>
                </div>
                <h3 class="text-center mb-4">
                    <a class="text-muted" href="./home">Go to Dashboard</a>
                </h3>
            </div>
        </div>
</section>
@endsection
