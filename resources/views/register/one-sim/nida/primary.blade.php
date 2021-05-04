
@extends('layout.app')

@section('title', 'Primary Registration')

@include('includes.registration.background')

@section('content')
    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <h4 class="content-heading">
                <div>NEW CUSTOMER REGISTRATION
                    <p class="lead mt-2">Register Primary Number</p>
                </div>
            </h4>

            <primary-nida></primary-nida>

        </div>

    </section>
@endsection

