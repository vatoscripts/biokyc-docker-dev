<!-- Stored in resources/views/child.blade.php -->

@extends('layout.auth')

@section('title', 'OTP')

@section('sidebar')
    @parent

    <p>This is appended to the master sidebar.</p>
@endsection

@section('content')
    <!-- START card-->
    <div class="card card-flat">
        <div class="card-header text-center bg-dark">
            <a href="#">
                <img class="block-center rounded" src="{{ asset('img/logo.svg') }}" width="190" height="60" alt="Image">
            </a>
        </div>

        @include('layout.flash-messages')

        <div class="card-body">
            <h4><p class="text-center py-2"><strong>One Time Pin (OTP)</strong></p></h4>
                <form method="post" action="{{ action('User\UserController@validateOtp') }}" class="mb-3" id="loginForm" novalidate>
                        @csrf
                    <p class="text-center">Enter your 6 digits PIN sent to {{ $msisdn }} to complete signin.</p>
                    <div class="form-group">
                        <!----  <label class="text-muted" for="resetInputEmail1">PIN</label>-->
                        <div class="input-group with-focus">
                            <input name="otp" class="form-control border-right-0" id="resetInputEmail1" type="text" placeholder="Enter your OTP e.g 122126" autocomplete="off">
                            <div class="input-group-append">
                                <span class="input-group-text text-muted bg-transparent border-left-0">
                            <em class="fa fa-key"></em>
                        </span>
                            </div>
                        </div>
                    </div>
                    <button class="btn btn-danger btn-block" type="submit">Verify PIN</button>
                    <div class="float-right">
                        <a class="text-lg-right font-weight-bold" href="resend-otp" >Resend PIN?</a>
                    </div>
                </form>
        </div>
    </div>
    <!-- END card-->
@endsection
