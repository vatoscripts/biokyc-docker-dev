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
            <p class="text-center py-2 h4"><strong>PASSWORD RESET</strong></p>
            <form method="post" action="{{ action('UserController@getResetPassowordToken') }}" class="mb-3" id="loginForm" novalidate>
                @csrf
                <div class="form-group">
                    <!---- <label class="text-muted" for="resetInputEmail1">Email address</label> -->
                    <div class="input-group with-focus">
                        <input name="reset_password_email" class="form-control border-right-0" id="resetInputEmail1" type="email" placeholder="Enter your email address" autocomplete="off">
                        <div class="input-group-append">
                            <span class="input-group-text text-muted bg-transparent border-left-0">
                        <em class="fa fa-envelope"></em>
                    </span>
                        </div>
                    </div>
                </div>
                <button class="btn btn-danger btn-block" type="submit">Reset Password</button>
                <div class="float-left">
                    <a class="text-lg-right font-weight-bold" href="/">Back to Login?</a>
                </div>
                <div class="float-right">
                    <a class="text-lg-right font-weight-bold" href="./recover-password-sms">Recover by Phone</a>
                </div>
            </form>
        </div>

    </div>
    <!-- END card-->
@endsection
