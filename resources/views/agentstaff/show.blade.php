@extends('layout.app')

@section('content')

<!-- Main section-->
<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">
        @include('layout.flash-messages')
        <div class="staff-details row">

            <div class="col-lg-4 col-sm-12">

                <div class="card b">
                    <div class="card-body text-center">
                        <div class="py-4">
                            <img class="img-fluid rounded-circle" src="data:image/png;base64, {{$staff['Photo']}}" alt="Contact">
                        </div>

                        <h3 class="m-0 text-bold">{{ $staff['FirstName']}} {{ $staff['MiddleName']}} {{ $staff['Surname']}}</h3>
                        <div class="text text-success m-2"> <em class="fa fa-check-circle fa-3x"></em></div>
                    </div>
                </div>

                @if ($staff['Status']=='Y' )
                    <a id="block-staff-link" href="/block-agentstaff/{{ $staff['AgentStaffID'] }}" class="btn btn-block btn-lg btn-outline-danger text-bold"> Deactivate this staff</a>
                @else
                    <a id="unblock-staff-link" href="/unblock-agentstaff/{{ $staff['AgentStaffID'] }}" class="btn btn-block btn-lg btn-outline-info text-bold"> Activate this staff</em></a>
                @endif

                @if ($staff['DeviceID'])
                    <div class="my-3">
                        <form method="post" action="{{ action('KYA\AgentStaffController@clearIMSDevice') }}" class="mb-3" novalidate>
                            @csrf
                            <input type="hidden" name="agentStaffID" value="{{ $staff['AgentStaffID'] }}">
                            <button type="submit" class="btn btn-block btn-lg btn-outline-warning text-bold"> Clear Device from Staff</button>
                        </form>
                    </div>
                @endif

            </div>
            <div class="col-lg-8 col-sm-12">
                <div class="card b">
                    <div class="card-header d-flex align-items-center">
                        <div class="h3">Contact Information</div>
                    </div>
                    <div class="card-body">
                        <div class="row py-4 justify-content-center">
                            <div class="col-12 col-sm-10">
                                <form class="form-horizontal">
                                    <div class="form-group row">
                                        <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact1">Business  Name</label>
                                        <div class="col-xl-9 col-md-9 col-8">
                                            <input class="form-control" id="inputContact1" type="text" placeholder="" value="{{ $staff['BusinessName']}} " disabled>
                                        </div>
                                    </div>
                                    <div class="form-group row">
                                        <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact2">NIN</label>
                                        <div class="col-xl-9 col-md-9 col-8">
                                            <input class="form-control" id="inputContact2" type="email" value="{{ $staff['NIN']}}" disabled>
                                        </div>
                                    </div>

                                    <div class="form-group row">
                                        <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact6">Address</label>
                                        <div class="col-xl-9 col-md-9 col-8">
                                            <textarea class="form-control text-capitalize" id="inputContact6" rows="2" disabled>{{ $staff['NIDAVillage']}}, {{ $staff['NIDAWard']}} , {{ $staff['NIDADistrict']}}, {{ $staff['NIDARegion']}}</textarea>
                                        </div>
                                    </div>

                                    <div class="form-group row">
                                        <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact4">Agent</label>
                                        <div class="col-xl-9 col-md-9 col-8">
                                            <a href="/agent/{{$staff['AgentID']}}" class="btn btn-link"><h4>{{$staff['BusinessName']}}</h4></i></a>
                                        </div>
                                    </div>

                                </form>

                            </div>
                        </div>

                    </div>

                </div>
                @if (($staff['DeviceID']==="" || $staff['DeviceID']==null) && $staff['OnboardedToImsYN']=='N')
                    <div class="card b">
                        <div class="card-body">
                            <a  class="mb-1 btn-lg btn btn-outline-danger float-right text-bold" href="/staff-verify-ims/{{$staff['AgentStaffID']}}">
                                <em class="fa-2x mr-2 far fa-handshake"></em> Verify Staff
                            </a>
                        </div>
                    </div>
                @endif

                @if ($staff['OnboardedToImsYN'] === 'Y')
                    <div class="card b">
                        <div class="card-header">
                            <div class="h3">ONBOARDING DETAILS</div>
                        </div>
                        <div class="card-body">
                            <div class="form-group row">
                                <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact2">Date Onboarded</label>
                                <div class="col-xl-9 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value=" {{ date('D, jS F Y G:i:s', strtotime($staff['OnboardedDate'])) }}" disabled>
                                </div>
                            </div>

                            <div class="form-group row">
                                <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact2">Famoco ID</label>
                                <div class="col-xl-9 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{ $staff['DeviceID']}}" disabled>
                                </div>
                            </div>

                            <div class="form-group row">
                                <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact2">Region</label>
                                <div class="col-xl-9 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{ $staff['ImsRegion']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact2">District</label>
                                <div class="col-xl-9 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{ $staff['ImsDistrict']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact2">Ward</label>
                                <div class="col-xl-9 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{ $staff['ImsWard']}}" disabled>
                                </div>
                            </div>
                            <div class="form-group row">
                                <label class="text-bold col-xl-3 col-md-3 col-4 col-form-label text-right" for="inputContact2">Village</label>
                                <div class="col-xl-9 col-md-9 col-8">
                                    <input class="form-control" id="inputContact2" type="email" value="{{ $staff['ImsVillage']}}" disabled>
                                </div>
                            </div>
                        </div>
                    </div>
                @endif


            </div>

        </div>
    </div>
</section>

@endsection

@section('scripts')

    @include('agentstaff.agent-staff-block-modal')

    @include('agentstaff.agent-staff-verify')

    @include('agentstaff.agent-staff-scripts')

    <script src="{{ asset('js/agentstaff.js') }}"></script>

@endsection
