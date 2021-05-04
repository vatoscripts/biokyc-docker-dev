<!-- Stored in resources/views/child.blade.php -->

@extends('layout.auth')

@section('title', 'Login')

@section('content')
    <!-- START card-->
    <div class="card card-flat">
        <div class="card-header text-center bg-dark">
            <a href="#">
                <img class="block-center rounded" src="{{ asset('img/logo.svg') }}" width="190" height="60" alt="Image">
            </a>
        </div>

        @include('layout.flash-messages')

        @if (session::has('remaining') && (session::get('remaining') !==0))
            <div class="border border-danger text-danger h5 p-1 mt-1 lead mb-1" align="center">
                Only {!! Session::get('remaining') !!} login attempts remaining !
            </div>
        @endif

        <div class="card-body">
            <p class="text-center py-2 h4"><strong>VTL BioKYC Portal</strong></p>
            <form method="post" action="{{ action('User\UserController@login') }}" class="mb-3" id="loginForm" novalidate>
                @csrf
                <div class="form-group">
                    <div class="input-group with-focus">
                        <input name="name" class="form-control border-right-0" id="exampleInputName" type="text" placeholder="Enter username">
                        <div class="input-group-append">
                            <span class="input-group-text text-muted bg-transparent border-left-0">
                              <em class="fa fa-user"></em>
                           </span>
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <div class="input-group with-focus">
                        <input name="password" class="form-control border-right-0" id="exampleInputPassword1" type="password" placeholder="Enter password">
                        <div class="input-group-append">
                            <span class="input-group-text text-muted bg-transparent border-left-0">
                              <em class="fa fa-lock"></em>
                           </span>
                        </div>
                    </div>
                </div>
                <div class="checkbox c-checkbox mt-0">
                    <label>
                        <input type="checkbox" value="1" required name="terms-conditions">
                        <span class="fa fa-check"></span> I agree with the
                        <a class="ml-1"  href="#" id="swal-demo2">terms and conditions</a>
                    </label>
                </div>

                <button name="login" class="btn btn-block btn-danger mt-3" type="submit">Login</button>
                <div class="clearfix">

                    <div class="float-right">
                        <a class="text-lg-right font-weight-bold" href="/recover-password-sms">Forgot your password?</a>
                    </div>
                </div>
            </form>
        </div>
    </div>
    <!-- END card-->
@endsection
