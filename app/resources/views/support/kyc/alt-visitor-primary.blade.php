
@extends('layout.app')

@section('title', 'View All Registrations')

@section('content')

<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper" style="overflow-y: hidden">

        <h4 class="content-heading">
            <div>VISITOR ALTERNATIVE REGISTRATIONS
                <p class="lead mt-2">View All</p>
            </div>
        </h4>

        <alt-visitor-all></alt-visitor-all>

    </div>

</section>
@endsection
