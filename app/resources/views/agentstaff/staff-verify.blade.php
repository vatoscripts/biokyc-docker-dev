@extends('layout.app')

@section('content')

<!-- Main section-->
<section class="section-container">


    <!-- Page content-->
    <div class="content-wrapper">
        <div class="row">

                <div class="col-lg-12 col-sm-12">
                    <h4 class="content-heading">
                        <div>Agent Onboarding
                            <p class="lead mt-2">KYA Details: IMS Verify</p>
                        </div>
                    </h4>
                    @include('layout.flash-messages')


                    <form method="post" action="{{ action('KYA\AgentStaffController@verifyAgentIMS1') }}" class="mb-3" id="staffVerify" novalidate>
                        @csrf
                        <input type="hidden" id="agentstaff_Id" value="{{$agentID}}" name="agentID">
                        <div class="form-group row">
                            <label for="exampleInputEmail1" class="col-sm-3 col-form-label">Device ID</label>
                            <div class="col-sm-9">
                                <input id="DeviceID" name="DeviceID" class="form-control" type="text" placeholder="Enter FAMOCO Device ID" required>
                            </div>
                        </div>

                        <button id="PostVerifyIMS" type="submit" class="btn btn-lg btn-outline-danger  float-right text-bold"><span class="fa fa-save"></span> Verify Device</button>
                    </form>

                </div>
        </div>
    </div>
</section>
@endsection
