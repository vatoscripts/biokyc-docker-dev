@extends('layout.app')

@section('content')

<!-- Page content-->
<div class="content-wrapper">
    <div class="content-heading">
        <div>Agent Onboarding
            <small>KYA Details: Agent recruitment.</small>
        </div>
    </div>

    @include('layout.flash-messages')

    <div class="row">
        <div class="col-lg-4">
            <div class="card card-default">
                <div class="card-body text-center">
                    <div class="py-4">
                        <img class="img-fluid rounded-circle img-thumbnail thumb200" src="{{ asset('img/user/user_default.png') }}" alt="Contact">
                    </div>
                    <h3 class="m-0 text-bold">{{ $item['BusinessName'] }}</h3>
                </div>
            </div>
            <div class="card card-default d-none d-lg-block">
                <div class="card-header">
                    <div class="card-title text-center">Recent Onboards</div>
                </div>
            </div>
        </div>
        <div class="col-lg-8">
            <div class="card card-default">
                <div class="card-header d-flex align-items-center">
                    <div class="d-flex justify-content-center col">
                        <div class="h4 m-0 text-center">Agent Information</div>
                    </div>

                </div>
                <div class="card-body">
                    <div class="row py-4 justify-content-center">
                        <div class="col-12 col-sm-10">
                            <form class="form-horizontal">
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact1">Name</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact1" disabled type="text" placeholder="" value="{{ $item['BusinessName'] }}">
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact2">AgentCode</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact2" disabled type="text" value="{{ $item['AgentCode'] }}">
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact3">TIN Number</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact3" disabled type="text" value="{{ $item['TIN'] }}">
                                    </div>
                                </div>
                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact4">Business Licence Number</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact4" disabled type="text" value="{{ $item['BusinessLicenceNo'] }}">
                                    </div>
                                </div>

                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact6">Address</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <textarea class="form-control" id="inputContact6" disabled rows="4">{{ $item['Address'] }}</textarea>
                                    </div>
                                </div>

                                <div class="form-group row">
                                    <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact8">Zone</label>
                                    <div class="col-xl-10 col-md-9 col-8">
                                        <input class="form-control" id="inputContact8" disabled type="text" value="{{ $item['ZoneName'] }}">
                                    </div>
                                </div>
                            </form>

                            <hr />
                            <div class="" id="block_agent_div">

                                <fieldset>
                                    <legend>Block Agent</legend>
                                    <form action="{{ URL::to('block-agent') }}" method="post">
                                        @csrf
                                        <input type="hidden" name="AgentID" value="{{ $item['AgentID'] }}">
                                        <div class="form-group row">
                                            <label class="text-bold col-xl-2 col-md-3 col-4 col-form-label text-right" for="inputContact6">Reasons for blocking</label>
                                            <div class="col-xl-10 col-md-9 col-8">
                                                <textarea class="form-control" id="block_reason" name="DeactivateReason" rows="4"></textarea>
                                            </div>
                                        </div>
                                        <div class="text-right">
                                            <input type="submit" value="Block Agent" id="block_agent" class="btn btn-danger mt-4 mb-2">
                                        </div>
                                    </form>
                                </fieldset>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

@endsection
