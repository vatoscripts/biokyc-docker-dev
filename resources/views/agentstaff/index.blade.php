@extends('layout.app')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <h3>AgentStaff Onboarding
                    {{-- <p class="lead mt-2">Vivamus sagittis lacus luctus.</p> --}}
                </h3>
            </div>

                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <!-- START chart-->
                        <!-- Button trigger modal -->
                        @include('layout.flash-messages')
                        <div class="card b">
                            <div class="card-body">
                                <!---modal button-->
                                <button type="button" class="btn btn-dark float-right" data-target="#agent_register" data-toggle="modal">
                                    <span class="fa fa-bars"></span> New Staff Agent
                                </button>
                                <!---modal button ends-->
                            </div>
                        </div>

                        <!-- END chart-->
                        <div class="row">
                            <div class="col-xl-12">

                                <!-- DATATABLE DEMO 2-->
                                <div class="card">
                                    <div class="card-body">
                                        @if ($agentstaff)
                                        <table class="table table-striped my-4 w-100" id="datatable1">
                                            <thead>
                                                <tr>
                                                    <th>Full Name</th>
                                                    <th>Business Name</th>
                                                    <th>Active</th>
                                                    <th>Action</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                @foreach ($agentstaff as $staff)
                                                    <tr class="gradeX">
                                                    <td>{{$staff['FirstName']}} {{$staff['Surname']}}</td>
                                                    <td>{{$staff['BusinessName']}}</td>
                                                    <td>
                                                            @if ($staff['ActiveYN'] === 'Y')
                                                            <div class="badge badge-success" href="">Active</div>
                                                        @else
                                                            <div class="badge badge-danger" href="">Not Active</div>
                                                        @endif
                                                    </td>
                                                    <td><a href="/agent-staff/{{$staff['AgentStaffID']}}" class="btn btn-square btn-info">
                                                            <i class="fa fa-search mr-2"></i> View
                                                        </a>
                                                    </td>
                                                </tr>
                                                @endforeach
                                            </tbody>
                                        </table>
                                        @else
                                            <div class="card-body">
                                                <h3 class="text text-info lead"><strong>Looks like you do NOT have any staff yet. Create one by clicking on the above button !</strong></h3>
                                            </div>
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

    @include('agentstaff.agent-staff-modal')

    <script src="{{ asset('js/vtlbio.js') }}"></script>

    <script>
        var x = new VTLBion();
        x.Init("Div_fingerprint");
    </script>

    <script src="{{ asset('js/agent-staff-create.js') }}"></script>

@endsection
