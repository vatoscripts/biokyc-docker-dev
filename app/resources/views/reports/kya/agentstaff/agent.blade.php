@extends('layout.app')

@section('content')

<!-- Main section-->
<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">
        <div class="content-heading">
            <div>Staff Per Agent
                <p class="lead mt-2">KYA Reports: View Staff per Agent .</p>
            </div>
        </div>
        @include('layout.flash-messages')

        <form method="post" action="{{ action('Report\KYAReportController@staffByAgent') }}" class="mb-3" id="agentToForm" novalidate>
            @csrf
            <div class="card">
                <div class="card-body">
                    <div class="form-row">
                        <div class="form-group col-5">
                            <label for=""><strong>Choose Agent</strong></label>
                            <select name="agentFrom" class="form-control" onchange="getAgents()" id="agentFrom-dropdown">
                            </select>
                        </div>
                        <div class="form-group col-2">
                            <button id="agentFromBtn" type="submit" class="btn btn-lg btn-outline-danger btn-block float-left text-bold mt-3"><span class="fa fa-save fa-2x"></span> Load Staff</button>
                        </div>
                    </div>
                </div>
            </div>
        </form>

        @if (isset($staff))
            <!-- DATATABLE DEMO 2-->
            <div class="card" id="agentsbyLocationWrapper">
                <div class="card-body ">
                    @if (count($staff) > 0)
                    <div class="agentsbyLocationReport">
                        <div id="agentsCount" class=""></div>
                        <table class="table table-striped my-4 w-100" id="staffbyAgentTable">
                            <thead>
                                <tr>
                                    <th>Full Name</th>
                                    <th>Business Name</th>
                                    <th>Active</th>
                                    <th class="">Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                @foreach ($staff as $staffAgent)
                                <tr class="gradeX">
                                    <td>{{$staffAgent['FirstName']}} {{$staffAgent['Surname']}}</td>
                                    <td class="d-none d-sm-block">{{$staffAgent['BusinessName']}}</td>
                                    <td>
                                        @if ($staffAgent['ActiveYN'] === 'Y')
                                            <div class="badge badge-success">Active</div>
                                        @else
                                            <div class="badge badge-danger">Not Active</div>
                                        @endif
                                    </td>
                                    <td>
                                        @if ($staffAgent['OnboardedToImsYN'] === 'Y')
                                            <div class="badge badge-success">Onboarded</div>
                                        @else
                                            <div class="badge badge-danger">Not Onboarded</div>
                                        @endif
                                    </td>
                                    <td>
                                        <a href="/agent-staff/{{$staffAgent['AgentStaffID']}}" class="btn btn-square btn-info">
                                            <i class="fa fa-search mr-2"></i> View
                                        </a>
                                    </td>
                                </tr>
                                @endforeach
                            </tbody>
                        </table>
                    </div>

                    @else
                        <div class="h4 text-danger lead">Oops ! Looks like there are no any Staff(s) for the specified Agent.</div>
                    @endif

                </div>
            </div>
        @endif

    </div>
</section>

@endsection

@section('scripts')

    {{-- @include('agentstaff.agent-staff-block-modal')

    @include('agentstaff.agent-staff-verify')

    @include('agentstaff.agent-staff-scripts') --}}

    <script src="{{ asset('js/agentStaffReport.js') }}"></script>

@endsection

