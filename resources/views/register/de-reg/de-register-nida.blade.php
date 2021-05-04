@extends('layout.app')

@include('includes.registration.background')

@section('title', 'Customer De-Registration')

@section('content')

<section class="section-container">
    <!--Main Page content-->
    <div class="content-wrapper">

        <h4 class="content-heading">
            <div>DE-REGISTER CUSTOMER MSISDN
                <p class="lead mt-2">Check NIDA</p>
            </div>
        </h4>

        <dereg-nida></dereg-nida>

    </div>

</section>
@endsection
