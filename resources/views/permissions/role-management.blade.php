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
                            <form action="{{ action('RoleManagementController@saveRoleRights') }}" method="post">
                                @csrf
                                <div class="form-row">

                                    <div class="col-md-5">
                                        <div class="card">
                                            <div class="card-header">ROLES</div>
                                            <div class="card-body">
                                                @foreach ($roles as $role)

                                                    <label class="ml-4" for="role_{{ $role['ID'] }}"> <input type="radio" onchange="RoleSelected(this)"  value="{{ $role['ID'] }}" id="role_{{ $role['ID'] }}" name="roles-radio" class="form-check-input">{{ $role['Description'] }}</label> <br>

                                                @endforeach
                                            </div>
                                        </div>

                                    </div>

                                    <div class="col-md-7">
                                        <div class="card">
                                            <div class="card-header">RIGHTS</div>
                                            <div id="divekycTreview" class="card-body"></div>
                                        </div>

                                        <button id="saveUserRoleRights" class="btn btn-outline-danger" type="submit">Save</button>
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
//JKYCObject = {{}}///JSON.parse('{"Row":[{"ID": 10, "Description":"Agent", "ParentID":0},{"ID": 1001, "Description":"Agent List", "ParentID":10},{"ID": 1002, "Description":"Add Agent", "ParentID":10},{"ID": 11, "Description":"Staff Agent", "ParentID":0},{"ID": 1101, "Description":"Staff Agent List", "ParentID":11},{"ID": 1102, "Description":"Add Staff Agent", "ParentID":11},{"ID": 110201, "Description":"Add Child", "ParentID":1102}]}')






</script>


@endsection

