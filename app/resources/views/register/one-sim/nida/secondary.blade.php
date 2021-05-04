
@extends('layout.app')

@section('title', 'Secondary Registration')

@include('includes.registration.background')

@section('content')
    <section class="section-container">
        <!--Main Page content-->
        <div class="content-wrapper">

            <h4 class="content-heading">
                <div>NEW CUSTOMER REGISTRATION
                    <p class="lead mt-2">Register Secondary Number</p>
                </div>
            </h4>

            <secondary-nida></secondary-nida>

        </div>

    </section>
@endsection

