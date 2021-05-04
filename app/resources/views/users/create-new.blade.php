@extends('layout.app')

@include('includes.registration.background')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Create New User
                    <p class="lead mt-2">KYA Details: Add New User</p>
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
                                <button type="button" class="btn btn-dark float-right" data-target="#user-register-new" data-toggle="modal">
                                        <span class="fa fa-bars"></span> New User</button>
                                <!---modal button ends-->
                            </div>
                        </div>

                        <!-- END chart-->
                        <div class="row">
                            <div class="col-xl-12">
                                <div class="card">
                                    <div class="card-body">
                                       <table class="table table-striped table-hover w-100" id="datatable1">
                                          <thead>
                                             <tr>
                                                <th data-priority="1">UserName</th>
                                                <th>Role</th>
                                                <th>Phone</th>
                                                <th>Email</th>
                                                <th>Domain User</th>
                                                <th>Created By</th>
                                                <th>Created Date</th>
                                                <th data-priority="2">Active User</th>
                                             </tr>
                                          </thead>
                                          <tbody>
                                              @foreach ($users as $item)
                                                <tr>
                                                    <td>{{$item['username']}}</td>
                                                    <td>{{$item['RoleName']}}</td>
                                                    <td>{{$item['phone']}}</td>
                                                    <td>{{$item['email']}}</td>
                                                    <td>{{$item['IsAD']}}</td>
                                                    <td>{{$item['CreatedBy']}}</td>
                                                    <td>{{ date('Y-m-d h:i:s', strtotime($item['CreatedDate']))  }}</td>
                                                    <td>{{$item['ActiveYN']}}</td>
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
                </div>
        </div>

    </section>
@endsection

@section('scripts')

    @include('users.create-new-user-modal')

    <script src="{{ asset('js/create-new-user.js') }}"></script>

@endsection
