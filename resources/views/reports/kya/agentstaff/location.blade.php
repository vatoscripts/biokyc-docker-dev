@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Agent Staff Reports
                    <p class="lead mt-2">KYA Reports: Agent Staff per Location.</p>
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
                                <form method="post" action="{{ action('Report\KYAReportController@getStaffByLocation') }}" class="mb-3" id="agentsByLocation" novalidate>
                                    @csrf
                                    <div class="form-row">

                                        <div class="form-group col-md-3 col-xs-12">
                                            <label for=""><strong>REGION</strong></label>
                                            <select name="region" class="form-control" onchange="getdistrict(this)" id="region-dropdown">
                                            </select>
                                        </div>

                                        <div class="form-group col-md-2 col-xs-12">
                                            <label for=""><strong>DISTRICT</strong></label>
                                            <select name="district" class="form-control" onchange="getWards(this)"id="district-dropdown">
                                            </select>
                                        </div>

                                        <div class="form-group col-md-2 col-xs-12">
                                            <label for=""><strong>WARD</strong></label>
                                            <select class="form-control" name="ward" onchange="getVillage(this)" id="ward-dropdown"></select>
                                            </select>
                                        </div>

                                        <div class="form-group col-md-3 col-xs-12">
                                            <label for=""><strong>VILLAGE</strong></label>
                                            <select class="form-control" name="village"  id="village-dropdown"></select>
                                            </select>
                                        </div>

                                        <div class="form-group col-md-2 col-xs-12">
                                            <button id="agentStaffByLocationBtn" type="submit" class="btn btn-lg btn-block btn-outline-danger text-bold mt-4">Filter</button>
                                        </div>
                                    </div>

                                </form>
                            </div>

                        </div>

                        {{-- @if (isset($staff)) --}}
            <!-- DATATABLE DEMO 2-->
            <div class="card" id="agentsbyLocationWrapper">
                <div class="card-body ">
                    {{-- @if (count($staff) > 0) --}}
                    <div class="agentsbyLocationReport">
                        <div id="agentsCount" class=""></div>
                        <table class="table table-striped my-4 w-100" id="agentstaffbyLocationTable">
                            <thead>
                                <tr>
                                    <th>Full Name</th>
                                    <th>Business Name</th>
                                    <th>Region</th>
                                    <th class="">District</th>
                                    <th>Date Onboarded</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{-- @foreach ($staff as $staffAgent)
                                <tr class="gradeX">
                                    <td>{{$staffAgent['FirstName']}} {{$staffAgent['Surname']}}</td>
                                    <td class="">{{$staffAgent['BusinessName']}}</td>
                                    <td>{{$staffAgent['ImsRegion']}}</td>
                                    <td class="">{{$staffAgent['ImsDistrict']}}</td>
                                    <td class="">
                                            @if ($staffAgent['ActiveYN'] === 'Y')
                                            <div class="badge badge-success">Active</div>
                                            @else
                                                <div class="badge badge-danger">Not Active</div>
                                            @endif
                                    </td>
                                </tr>
                                @endforeach --}}
                            </tbody>
                        </table>
                    </div>

                    {{-- @else
                        <div class="h4 text-danger lead">Oops ! Looks like there are no any Staff(s) for the specified Agent.</div>
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

<script src="{{ asset('js/agentstaff.js') }}"></script>
<script src="{{ asset('js/agentstaffLocation.js') }}"></script>
@endsection

