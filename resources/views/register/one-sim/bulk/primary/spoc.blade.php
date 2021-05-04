@extends('layout.app')

@section('title', 'Register company - Primary')

@include('includes.dashboard.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <h4 class="content-heading">
                <div>BULK REGISTRATION - PRIMARY MSISDN
                    <p class="lead mt-2">SPOC Details</p>
                </div>
            </h4>

            <primary-spoc></primary-spoc>

        </div>

    </section>
@endsection


