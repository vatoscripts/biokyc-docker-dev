@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Roles Management
                    <p class="lead mt-2">KYA Reports: Agents per Location.</p>
                </div>
            </div>

            @include('layout.flash-messages')

            <!-- START cards box-->
                <!-- END cards box-->
                <div class="">
                    <!-- START dashboard main content-->
                    <div class="">
                        <div class="">
                            <form action="{{ action('UserManagementController@saveUserManagement') }}" method="post">
                                @csrf
                                <div class="form-row">

                                    <div class="col-md-5">
                                        <div class="card" id="userManagementList">
                                            <div class="card-header">USERS</div>
                                            <div class="card-body">
                                                @foreach ($users as $employee)
                                                    <label class="ml-4" for="user_{{ $employee['UserID'] }}"> <input type="radio" onchange="UserSelected(this)"  value="{{ $employee['UserID'] }}" id="user_{{ $employee['UserID'] }}" name="user-management-radio" class="form-check-input">{{ $employee['Username'] }}</label> <br>
                                                @endforeach
                                            </div>
                                        </div>
                                    </div>

                                    <div class="col-md-7">
                                        <div class="card">
                                            <div class="card-header">RIGHTS</div>
                                            <div id="" class="card-body">
                                                <div class="form-row">
                                                    <div class="col-md-8 col-xs-12 mb-3">
                                                        <label for=""><strong>Roles</strong></label>
                                                        <select class="form-control" name="user-role-management"  id="agent-category-dropdown">
                                                            @foreach ($roles as $role)
                                                                <option value='{{ $role['ID'] }}' >{{ $role['Description'] }}</option>
                                                            @endforeach
                                                        </select>
                                                    </div>
                                                </div>

                                                <div class="form-row">
                                                    <div class="col-md-8 col-xs-12 mb-3">
                                                        <label for=""><strong>Level</strong></label>
                                                        <select class="form-control" name="user-level-management"  id="agent-category-dropdown">
                                                            @foreach ($levels as $level)
                                                                <option value='{{ $level['LevelID'] }}' >{{ $level['Description'] }}</option>
                                                            @endforeach
                                                        </select>
                                                    </div>
                                                </div>

                                                <div class="form-row">
                                                    <div class="col-md-8 col-xs-12 mb-3">
                                                        <label for=""><strong>Group</strong></label>
                                                        <select class="form-control" name="user-group-management"  id="agent-category-dropdown">
                                                            @foreach ($groups as $group)
                                                                <option value='{{ $group['GroupID'] }}' >{{ $group['GroupName'] }}</option>
                                                            @endforeach
                                                        </select>
                                                    </div>
                                                </div>

                                            </div>
                                        </div>

                                        <button id="saveUserManagementBtn" class="btn btn-outline-danger" type="submit">Save</button>
                                    </div>
                                </div>

                            </form>

                        </div>

                    </div>
                    <!-- END dashboard main content-->
                </div>
        </div>

    </section>


@endsection

@section('scripts')
<script src="{{ asset('js/role-management.js') }}"></script>
<script>

</script>


@endsection

