@extends('layout.app')

@section('content')

<!-- Main section-->
<section class="section-container">

    <!-- Page content-->
    <div class="content-wrapper">

        <div class="row">

            <div class="col-lg-12 col-sm-12">

                    @include('layout.flash-messages')
                    <form method="post" action="{{ action('KYA\AgentStaffController@onboardAgentIMS1') }}" class="mb-3" id="staffOnboard" novalidate>
                        @csrf
                        <div class="form-row">
                            <div class="col-md-12 col-xs-12 mb-3">
                                <input name="isShared" class="form-check-input" id="isShared[]" type="checkbox" value="true">
                                <label class="form-check-label"> Shared Device</label>
                            </div>
                        </div>

                        <!--START OF REGIONS-->
                        <input type="hidden" id="regionID" name="regionID" value="{{ $region }}">
                        <input type="hidden" id="deviceID" name="deviceID" value="{{ $deviceID }}">
                        <input type="hidden" id="staffID" name="staffID" value="{{ $staffID }}">

                        <div class="form-row">
                            <div class="col-md-12 col-xs-12 mb-3">
                                <select name="district" class="form-control" onchange="getWards(this)"id="district-dropdown">
                                </select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="col-md-12 col-xs-12 mb-3">
                                <select class="form-control" name="ward" onchange="getVillage(this)" id="ward-dropdown"></select>
                            </div>
                        </div>

                        <div class="form-row">
                            <div class="col-md-12 col-xs-12 mb-3">
                                <select class="form-control" name="village"  id="village-dropdown"></select>
                            </div>
                        </div>

                        <button id="OnboardIMS" type="submit" class="btn btn-lg btn-outline-danger  float-right text-bold"><span class="fa fa-save"></span> Onboard</button>
                    </form>
            </div>
        </div>
    </div>
</section>
@endsection

@section('scripts')
    <script src="{{ asset('js/agentstaff.js') }}"></script>
@endsection
