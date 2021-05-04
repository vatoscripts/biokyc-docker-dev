@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Agent Onboarding
                    <p class="lead mt-2">KYA Details: Agent recruitment.</p>
                </div>
            </div>

            @include('layout.flash-messages')

                <form method="post" action="{{ action('AgentStaffController@onboardAgentIMS1') }}" class="mb-3" id="agentsByZone" novalidate>
                    @csrf

                    <!--START OF REGIONS-->
                    <input type="hidden" id="zoneID" name="zoneID" value="">

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <select name="agentZone" class="form-control" onchange="getAgentZones(this)"id="zones-dropdown">
                            </select>
                        </div>
                    </div>

                    <button id="agentsByZoneBtn" type="submit" class="btn btn-lg btn-outline-danger  float-right text-bold"><span class="fa fa-save"></span> Onboard</button>
                </form>

                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">

                        <!-- END chart-->
                        <div class="row">
                            <div class="col-xl-12">

                                <!-- DATATABLE DEMO 2-->
                                <div class="card">
                                    <div class="card-body ">
                                        @if ($agents)
                                            <table class="table table-striped my-4 w-100" id="datatable2">
                                            <thead>
                                                <tr>
                                                    <th>Business Name</th>
                                                    <th class="d-none d-sm-block">Business Licence</th>
                                                    <th>Address/Location</th>
                                                    <th class="">Status</th>
                                                    <th>Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                @foreach ($agents as $agent)
                                                    <tr class="gradeX">
                                                    <td>{{$agent['BusinessName']}}</td>
                                                    <td class="d-none d-sm-block">{{$agent['BusinessLicenceNo']}}</td>
                                                    <td>{{$agent['Address']}}</td>
                                                    <td>
                                                        @if ($agent['ActiveYN'] === 'Y')
                                                            <div class="badge badge-success">Active</div>
                                                        @else
                                                            <div class="badge badge-danger">Not Active</div>
                                                        @endif
                                                    </td>
                                                    <td>
                                                        <a href="/agent/{{$agent['AgentID']}}" class="btn btn-square btn-info">
                                                            <i class="fa fa-search mr-2"></i> View
                                                        </a>
                                                    </td>
                                                </tr>
                                                @endforeach
                                            </tbody>
                                        </table>
                                        @else
                                            <h3 class="text text-info lead"><strong>Looks like there are no any Agent yet. Create one by clicking on the above button !</strong></h3>
                                        @endif

                                    </div>
                                </div>
                                <!-- DATATABLE-->
                            </div>
                        </div>

                    </div>
                    <!-- END dashboard main content-->
                </div>
        </div>

    </section>
@endsection

@section('scripts')

<script src="{{ asset('js/kyareports.js') }}"></script>

@endsection
