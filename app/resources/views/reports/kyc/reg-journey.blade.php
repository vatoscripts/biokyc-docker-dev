@extends('layout.app')

@section('title', 'KYC Reports')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>KYC Reports
                    <p class="lead mt-2">Customer Registration Journey.</p>
                </div>
            </div>

            <reg-journey></reg-journey>

        </div>

    </section>
@endsection


