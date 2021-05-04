
@extends('layout.app')

@section('title', 'Primary Registration')

@section('content')

<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper" style="overflow-y: hidden">

        <h4 class="content-heading">
            <div>CUSTOMER REGISTRATION DETAILS
                <p class="lead mt-2">Registration Details per ID Number</p>
            </div>
        </h4>

        <id-registration-details></id-registration-details>

    </div>

</section>
@endsection

