@extends('layout.app')

@section('content')


<!-- Page content-->
<div class="content-wrapper">
    <div class="content-heading">
        <div>Devices
            <small>KYA details: Devices managment.</small>
        </div>

    </div>
    <!-- START cards box-->
    <!-- END cards box-->
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-9">
            <!-- START chart-->
            <!-- Button trigger modal -->

            <a href="{{ URL::to('add-device') }}" class="btn btn-dark"><span class="fa fa-bars"></span>&nbsp;New Device</a>

            <!-- END chart-->
            <div class="row">
                <div class="col-xl-12">
                    <div class="card">
                        <div class="card-body">
                            <table class="table table-striped my-4 w-100" id="datatable2">
                                <thead>
                                    <tr>
                                        <th data-priority="1">ID</th>
                                        <th>Device ID</th>
                                        <th>Distribution model</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php $index = 0; ?>
                                    @foreach ($list as $list_item)
                                    <?php $index++; ?>
                                    <tr class="gradeX">
                                        <td>{{ $index }}</td>
                                        <td>{{ $list_item['DeviceID'] }}</td>
                                        <td>{{ $list_item['Shared'] ? 'Shared' : 'Not shared' }}</td>
                                        <td>{{ $list_item['ActiveYN'] == 'Y' ? 'Active' : 'Inactive' }}</td>
                                        <td><a class="btn btn-info" href="{{ URL::to('device-details/' . $list_item['DeviceID']) }}">View</a></td>
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

<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="agent_register" tabindex="-1">
    @if (Session::has('warning'))
    <div class="clearfix"></div>
    <div class="alert alert-warning mt-2 alert-dismissible fade show" role="alert" align='center'>
        <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
        {!! Session::get('warning') !!}
    </div>
    @endif

    @if (Session::has('info'))
    <div class="clearfix"></div>
    <div class="alert alert-info mt-2 alert-dismissible fade show" role="alert" align='center'>
        <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
        {!! Session::get('info') !!}
    </div>
    @endif

    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-warning" style="height:40px;">
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>

            </div>
            <div class="modal-body p-5">
                <form method="post" action="#" class="mb-3" id="loginForm" novalidate>
                    @csrf
                    <div class="form-group">
                        <div class="input-group with-focus">
                            <input name="phoneNumber" class="form-control border-right-0" id="exampleInputEmail1" type="text" placeholder="Enter Mobile Number" autocomplete="off" required>
                            <div class="input-group-append">
                                <span class="input-group-text text-muted bg-transparent border-left-0">
                                    <em class="fa fa-envelope"></em>
                                </span> &nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="margin-top:-16px;">
                                    <button class="btn btn-block btn-info mt-3" type="submit" onclick="openchecknumberbox();">
                                        <span class="fa fa-search-plus"></span>&nbsp;Check Number</button>
                            </div>
                        </div>
                    </div>
                    <div align="center" hidden></div>
                    <input class="form-control" type="text" placeholder="Enter NIDA number">
                    <div id="Div_fingerprint" class="margin-block-end: 10px;">

                    </div>

                </form>
            </div>
            <br /><br />

            @if (session('status'))
            <div class="alert alert-success">
                {{ session('status') }}
            </div>
            @endif

            <div class="modal-footer">
                <button class="btn btn-danger" data-dismiss="modal">Cancel</button>
                <button class="btn btn-primary"><span class="fa fa-edit"></span>&nbsp;Register</button>
            </div>
        </div>
    </div>
</div>
<!----end device register modal-->
<script>
    var x = new VTLBion();
    x.Init("Div_fingerprint");

    function submitValue() {
        $("#").val(x.FingerPrintData)
    }
</script>



@endsection