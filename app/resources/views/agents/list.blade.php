@extends('layout.app')

@section('content')

<!-- Page content-->
<div class="content-wrapper">
    <div class="content-heading">
        <div>Agent Onboarding
            <small>KYA details: Agent managment.</small>
        </div>
    </div>

    @include('layout.flash-messages')

    <!-- END cards box-->
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-9">
            <!-- START chart-->
            <!-- Button trigger modal -->

            <!---modal button-->
            <a href="{{ URL::to('check-icap') }}" class="btn btn-dark"><span class="fa fa-bars"></span>&nbsp;New Agent</a>
            <!---modal button ends-->

            <!-- END chart-->
            <div class="row">
                <div class="col-xl-12">
                    <div class="card">
                        <div class="card-body">
                            <table class="table table-striped my-4 w-100" id="datatable2">
                                <thead>
                                    <tr>
                                        <th data-priority="1">ID</th>
                                        <th>Business name</th>
                                        <th>TIN</th>
                                        <th>Business licence number</th>
                                        <th>Agent Code</th>
                                        <th>Zone</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    @foreach ($list as $list_item)
                                    <tr class="gradeX">
                                        <td></td>
                                        <td>{{ $list_item['BusinessName'] }}</td>
                                        <td>{{ $list_item['TIN'] }}</td>
                                        <td>{{ $list_item['BusinessLicenceNo'] }}</td>
                                        <td>{{ $list_item['AgentCode'] }}</td>
                                        <td>{{ $list_item['ZoneName'] }}</td>
                                        <td><a class="btn btn-info" href="{{ URL::to('agent-details/' . $list_item['AgentID']) }}">View</a></td>
                                    </tr>
                                    @endforeach
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- END dashboard main content-->
        <!-- START dashboard sidebar-->
        <aside class="col-xl-3">
            <!-- START card-->
            <div class="card">
                <div class="card-body">
                    <div class="text-right text-muted"><em class="fa fa-gamepad fa-2x"></em></div>
                    <h3 class="mt-0">99</h3>
                    <p class="text-muted">Total Agents</p>
                    <div class="progress progress-xs mb-3">
                        <div class="progress-bar progress-bar-striped bg-warning" role="progressbar" aria-valuenow="60" aria-valuemin="0" aria-valuemax="70" style="width: 60%"><span class="sr-only">60% Complete</span></div>
                    </div>
                </div>
            </div>
            <!-- END card-->
            <!---=====TOP PERFORMER FOR ADMIN ONLY-->
            <div class="card card-default">
                <div class="card-header">
                    <div class="card-title">Available Devices</div>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID No 1</a>
                        </p>
                    </div>
                    <hr size="1">
                    </hr>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID No 2</a>
                        </p>
                    </div>
                    <hr size="1">
                    </hr>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID No 3</a>
                        </p>
                    </div>
                </div>
            </div>
            <div class="card card-default">
                <div class="card-header">
                    <div class="card-title">Fault Devices</div>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID #1</a>
                        </p>

                    </div>
                    <hr size="1">
                    </hr>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID #2</a>
                        </p>

                    </div>
                    <hr size="1">
                    </hr>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID #3</a>
                        </p>

                    </div>
                    <hr size="1">
                    </hr>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID #4</a>
                        </p>

                    </div>
                    <hr size="1">
                    </hr>
                    <div class="media-body text-truncate">
                        <p class="mb-1">
                            <a class="text-purple m-0" href="#">Device ID #5</a>
                        </p>

                    </div>
                </div>
            </div>
            <!-- END messages and activity-->
        </aside>
        <!-- END dashboard sidebar-->
    </div>
</div>

@endsection
