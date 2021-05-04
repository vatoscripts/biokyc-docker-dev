@extends('layout.app')

@section('content')

<!-- Page content-->
<div class="content-wrapper">
    <div class="content-heading">
        <div>Agent Onboarding
            <small>KYA details: Check phone number</small>
        </div>

    </div>
    <!-- START cards box-->
    <!-- END cards box-->
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-12">
            <div class="row">
                <div class="col-xl-12">
                    <div class="card">
                        <div class="card-body">

                            <div class="modal-dialog modal-lg">
                                <div class="modal-content">
                                    <div class="modal-header alert-warning" style="height:40px;">
                                        <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
                                    </div>
                                    <div class="modal-body p-5">

                                        @if(Session::has('message'))
                                        <div class="alert alert-danger">{{ Session::get('message') }}</div>
                                        @endif

                                        @if ($errors->any())
                                        <div class="alert alert-danger">
                                            <ul>
                                                @foreach ($errors->all() as $error)
                                                <li>{{ $error }}</li>
                                                @endforeach
                                            </ul>
                                        </div>
                                        @endif

                                        <form method="post" action="{{ url('post-check-icap') }}">
                                            @csrf
                                            <div class="form-group">
                                                <div class="input-group with-focus">
                                                    <input name="MSISDN" value="{{ old('MSISDN') }}" class="form-control border-right-0" id="number" type="text" placeholder="Enter Mobile Number" autocomplete="off" required>
                                                    <div class="input-group-append">
                                                        <span class="input-group-text text-muted bg-transparent border-left-0">
                                                            <em class="fa fa-envelope"></em>
                                                        </span>
                                                        <span style="margin-top:-16px;">
                                                            <button class="btn btn-block btn-info mt-3" type="submit">
                                                                <span class="fa fa-search-plus"></span>Check Number
                                                            </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- END dashboard main content-->
    </div>
</div>

@endsection