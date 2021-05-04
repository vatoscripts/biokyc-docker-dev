@extends('layout.app')

@section('title', 'New Registration ')

@section('content')
    <section class="section-container">
        <!--Main Page content-->
        <div class="content-wrapper">

            <h4 class="content-heading">
                <div>NEW CUSTOMER REGISTRATION
                    <p class="lead mt-2">Check Msisdn & NIDA ID</p>
                </div>
            </h4>

            <check-nida></check-nida>
        </div>

    </section>
@endsection
