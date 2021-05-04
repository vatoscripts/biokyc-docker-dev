<!-- Stored in resources/views/child.blade.php -->

@extends('layout.auth')

@section('title', 'Reset Password')

@section('sidebar')
    @parent

    <p>This is appended to the master sidebar.</p>
@endsection

@section('content')

    <!-- START card-->
    <div class="card card-flat">
        <div class="card-header text-center bg-dark">
            <a href="#">
                <img class="block-center rounded" src="img/logo.svg" width="190" height="60" alt="Image">
            </a>
        </div>

        @include('layout.flash-messages')

        <div class="card-body">
            <p class="text-center py-2 h4"><strong>PASSWORD RESET BY SMS</strong></p>
            <form method="post" action="{{ action('User\UserController@RecoverPasswordSMS') }}" class="mb-3" id="loginForm" novalidate>
                @csrf
                <div class="form-group">
                    <div class="input-group with-focus">
                        <input name="reset_password_phone" class="form-control border-right-0" id="resetpwdsms" type="text" placeholder="Enter your Phone Number" autocomplete="off">
                        <div class="input-group-append">
                            <span class="input-group-text text-muted bg-transparent border-left-0">
                                <em class="fa fa-phone"></em>
                            </span>
                        </div>
                    </div>
                </div>
                <button class="btn btn-danger btn-block" type="submit">Reset Password</button>
                <div class="float-left">
                    <a class="text-lg-right font-weight-bold" href="/">Back to Login?</a>
                </div>
            </form>
        </div>

    </div>
    <!-- END card-->
@endsection
