<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="user-register-new" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> CREATE NEW USER
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

            <div id="createUser" class="modal-body p-3">
                <form method="post" action="{{ action('User\UserManagementController@CreateNewUser') }}" class="mb-3" id="createUserForm" novalidate>
                    @csrf

                    <div class="form-group">
                        <label class="text-bold" for="userName">Domain UserName</label>
                        <input name="userName" type="text" class="form-control" placeholder="Enter Domain UserName">
                    </div>

                    <div class="form-group">
                        <label class="text-bold" for="mobile-phone">Mobile Number</label>
                        <input name="mobile-phone" type="text" class="form-control" placeholder="Enter Mobile Number starting with 255...">
                    </div>

                    <div class="form-group">
                        <div class="row">
                            <div class="col-3">
                                <label class="text-bold" for="roleName">Choose Role</label>
                            </div>
                            <div class="col-6">
                                <select class="custom-select" id="roleName-select" name="roleName">
                                    <option value=""> --- Choose User Role ---- </option>
                                    @foreach ($roles as $role)
                                        <option value="{{$role['ID']}}">{{$role['Description']}}</option>
                                    @endforeach
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="text-bold" for="email">Email</label>
                        <input id="email" name="email" class="form-control" type="email" placeholder="Enter Email Adress">
                    </div>

                    <div class="modal-footer">
                        <button id="cancelUser" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="createUserBtn" type="submit" class="btn btn-primary"><span class="fa fa-save"></span> Create Users</button>
                    </div>
                </form>
            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


