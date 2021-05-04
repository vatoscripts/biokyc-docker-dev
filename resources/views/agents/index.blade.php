@extends('layout.app')

@include('includes.registration.background')

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

            <!-- START cards box-->
                <!-- END cards box-->
                <div class="row">
                    <!-- START dashboard main content-->
                    <div class="col-xl-12">
                        <!-- START chart-->
                        <!-- Button trigger modal -->

                        <div class="card b">
                            <div class="card-body">
                                <!---modal button-->
                                <button type="button" class="btn btn-dark float-right" data-target="#agent-register-page1" data-toggle="modal">
                                        <span class="fa fa-bars"></span> New Agent</button>
                                <!---modal button ends-->
                            </div>
                        </div>

                        <!-- END chart-->
                        <div class="row">
                            <div class="col-xl-12">
                                <!-- DATATABLE DEMO 2-->
                                <div class="card">
                                    <div class="card-body ">
                                        @if ($agents)
                                            <table class="table table-striped my-4 w-100" id="datatable">
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

    @include('agents.agent-modal-page1')
    @include('agents.agent-modal-page2')

    <script src="{{ asset('js/agent-onboard.js') }}"></script>
    <script src="{{ asset('js/vtlbio.js') }}"></script>

        <script>
            var x = new VTLBion();
            x.Init("Div_fingerprint");

        </script>

    {{-- @include('agents.agent-save') --}}

@endsection
