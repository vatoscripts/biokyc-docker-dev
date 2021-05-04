@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Agent Reports
                    <p class="lead mt-2">KYA Reports: Agents per Location.</p>
                </div>
            </div>

            @include('layout.flash-messages')

            <!-- START cards box-->
                <!-- END cards box-->
                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <div class="card" id="filterAgentLocation">
                            <div class="card-body">
                                <form method="post" action="{{ action('Report\KYAReportController@fetchAgentsByLocation') }}" class="mb-3" id="agentsByLocation" novalidate>
                                    @csrf
                                    <div class="form-row">

                                        <div class="form-group col-md-3 col-xs-12">
                                            <label for=""><strong>ZONE</strong></label>
                                            <select name="agentZone" class="form-control" onchange="getregion(this)" id="zone-dropdown">
                                            </select>
                                        </div>

                                        <div class="form-group col-md-3 col-xs-12">
                                            <label for=""><strong>REGION</strong></label>
                                            <select name="agentRegion" class="form-control" onchange="getterritory(this)" id="region-dropdown">
                                            </select>
                                        </div>

                                        <div class="form-group col-md-3 col-xs-12">
                                            <label for=""><strong>TERRITORY</strong></label>
                                            <select name="agentTerritory" class="form-control" id="territory-dropdown">
                                            </select>
                                        </div>

                                        <div class="form-group col-md-3 col-xs-12">
                                            <button id="agentsByLocationBtn" type="submit" class="btn btn-lg btn-block btn-outline-danger text-bold mt-4">Filter</button>
                                        </div>
                                    </div>

                                </form>
                            </div>

                        </div>

                        {{-- <div class="card">
                            <div class="card-body">

                            </div>
                        </div> --}}
                        {{-- @if (isset($agents)) --}}
                        <!-- DATATABLE DEMO 2-->
                        <div class="card" id="agentsbyLocationWrapper">
                            <div class="card-body ">
                                <div class="agentsbyLocationReport">
                                    <div id="agentsCount" class=""></div>
                                    <table class="table table-striped my-4 w-100" id="agentsbyLocationTable">
                                        <thead>
                                            <tr>
                                                <th>Business Name</th>
                                                <th class="d-none d-sm-block">Business Location</th>
                                                <th>Region</th>
                                                <th class="">Status</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody >
                                            {{-- @foreach ($agents as $agent)
                                            <tr class="gradeX">
                                                <td>{{$agent['BusinessName']}}</td>
                                                <td class="d-none d-sm-block">{{$agent['ZoneName']}}</td>
                                                <td>{{$agent['RegionName']}}</td>
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
                                            @endforeach --}}
                                        </tbody>
                                    </table>
                                </div>
                                {{-- @if (count($agents) > 0) --}}

                                {{-- @else
                                    <div class="h4 text-danger lead">Oops ! Looks like there are no any Agent(s) for the specified location.</div>
                                @endif --}}

                            </div>
                        </div>
                        {{-- @endif --}}
                    </div>
                    <!-- END dashboard main content-->
                </div>
        </div>

    </section>
@endsection

@section('scripts')

<script src="{{ asset('js/agents.js') }}"></script>
<script src="{{ asset('js/kyareports.js') }}"></script>
@endsection

