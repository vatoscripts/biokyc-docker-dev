@extends('layout.app')

@section('title', 'Visitor Registration')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <h4 class="content-heading">
                <div>NEW VISITOR REGISTRATION
                    <p class="lead mt-2">Register Secondary Number</p>
                </div>
            </h4>

            <visitor-secondary></visitor-secondary>
        </div>

    </section>
@endsection

