@extends('layout.app')

@section('title', 'Visitor Registration')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Main Page content-->
        <div class="content-wrapper">

            <h4 class="content-heading">
                <div>NEW VISITOR REGISTRATION
                    <p class="lead mt-2">Register Primary Number</p>
                </div>
            </h4>

            <visitor-primary></visitor-primary>

        </div>

    </section>
@endsection

