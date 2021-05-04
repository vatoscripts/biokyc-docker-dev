@extends('layout.app')

@section('title', 'Register company - Secondary')

@include('includes.dashboard.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <h4 class="content-heading">
                <div>BULK REGISTRATION - SECONDARY MSISDN
                    <p class="lead mt-2">SPOC Details</p>
                </div>
            </h4>

            <secondary-spoc></secondary-spoc>

        </div>

    </section>
@endsection


