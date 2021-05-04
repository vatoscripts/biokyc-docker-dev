@extends('layout.app')

@section('title', 'Dashboard')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">
            <h4 class="content-heading">
                <div>Dashboard
                    <p class="lead mt-2">Welcome to eKYC Biometric Portal: <strong>{{$user['Surname']}}, {{$user['FirstName']}}</strong> </p>
                </div>
            </h4>
            <!-- START cards box-->
            @include('layout.flash-messages')
            <div class="row">
                <div class="col-xl-3 col-md-6">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-info-dark justify-content-center rounded-left">
                            <em class="icon-bell fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-primary rounded-right">
                            <div class="h2 mt-0">N/A</div>
                            <div class="text-uppercase">All Registration</a>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-xl-3 col-md-6">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-purple-dark justify-content-center rounded-left">
                            <em class="icon-check fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-green-light rounded-right">
                            <div class="h2 mt-0">N/A

                            </div>
                            <div class="text-uppercase">Current Regs</div>
                        </div>
                    </div>
                </div>
                <div class="col-xl-3 col-lg-6 col-md-12">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-green-dark justify-content-center rounded-left">
                            <em class="icon-equalizer fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-danger-light rounded-right">
                            <div class="h2 mt-0">N/A
                                <small></small>
                            </div>
                            <div class="text-uppercase">Decline ICAP</div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-lg-6 col-md-12">
                    <!-- START card-->
                    <div class="card flex-row align-items-center align-items-stretch border-0">
                        <div class="col-4 d-flex align-items-center bg-green-dark justify-content-center rounded-left">
                            <em class="icon-equalizer fa-3x"></em>
                        </div>
                        <div class="col-8 py-3 bg-danger-light rounded-right">
                            <div class="h2 mt-0">N/A
                                <small></small>
                            </div>
                            <div class="text-uppercase">Failed VERIFICATION</div>
                        </div>
                    </div>
                </div>

            </div>

        </div>

    </section>

@endsection
