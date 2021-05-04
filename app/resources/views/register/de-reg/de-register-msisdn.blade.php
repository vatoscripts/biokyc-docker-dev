@extends('layout.app')

@section('title', 'Customer De-Registration')

@section('content')

<section class="section-container">
    <!--Main Page content-->
    <div class="content-wrapper">

        <h4 class="content-heading">
            <div>DE-REGISTER CUSTOMER MSISDN
                <p class="lead mt-2">Choose MSISDN</p>
            </div>
        </h4>

        <dereg-msisdn></dereg-msisdn>

    </div>

</section>
@endsection
