<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="new-minor-register-page2" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header alert-danger" style="height:40px;"> MINOR DETAILS
                <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
            </div>

            <blockquote id="error-message"></blockquote>

            <div id="AgentSave" class="modal-body p-3">

                    <form id="MinorregisterNewMSISDNForm2" method="post" action="{{ action('KYCController@registerMinorSave_page2') }}" class="mb-3" enctype="multipart/form-data">
                    @csrf

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">First Name</label>
                            <input name="firstName" type="text" class="form-control" id="validationTooltip01" placeholder="Enter Minor First Name">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Middle Name</label>
                            <input name="middleName" type="text" class="form-control" id="validationTooltip01" placeholder="Enter Minor Middle Name">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Last Name</label>
                            <input name="lastName" type="text" class="form-control" id="validationTooltip01" placeholder="Enter Minor Last Name">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold">DOB </label>
                            <input class="form-control"  name="dob" placeholder="Enter Date of Birth Like 31121900">
                        </div>
                    </div>


                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold">Gender </label>
                            <select class="custom-select" id="gender-select" name="gender">
                                <option value="">SELECT GENDER</option>
                                <option value="MALE">MALE</option>
                                <option value="FEMALE">FEMALE</option>
                                <option value="UNSPECIFIED">UNSPECIFIED</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-6 col-xs-6 mb-3">
                            <label class="text-bold">ID TYPE </label>
                            <select class="custom-select" id="ID-select" name="ID-select">
                                <option value="">SELECT ID TYPE</option>
                                <option value="MALE">Passport</option>
                                <option value="FEMALE">Birth Certificate</option>
                                <option value="UNSPECIFIED">Adoption Document</option>
                            </select>
                        </div>
                        <div class="col-md-6 col-xs-6 mb-3">
                            <label class="text-bold">ID NUMBER </label>
                            <input class="form-control"  name="ID-number" placeholder="Enter Date of Birth Like 31121900">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-12 col-xs-12 mb-3">
                            <label class="text-bold">Nationality </label>
                            <select class="custom-select" id="country-select" name="country">
                                <option value="">SELECT COUNTRY</option>
                                @foreach ($country as $item)
                                    <option value="{{$item['Code']}}">{{$item['Name']}}</option>
                                @endforeach
                            </select>
                        </div>
                    </div>


                    <div class="form-row">
                        <div class="col-md-7 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">ID Photo</label>
                            <div class="custom-file">
                                <input type="file" class="form-control-file" name="minor-ID-photo-file" id="minor-ID-photo-file" aria-describedby="TINfileHelp">
                            </div>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-7 col-xs-12 mb-3">
                            <label class="text-bold" for="exampleInputEmail1">Potrait Photo</label>
                            <div class="custom-file">
                                <input type="file" class="form-control-file" name="minor-potrait-photo-file" id="minor-potrait-photo-file" aria-describedby="LicencefileHelp">
                            </div>
                        </div>
                    </div>

                    <div class="modal-footer">
                        <button id="cancelSaveAgent" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                        <button id="newMinorRegSave" type="submit" class="btn btn-primary"> Register Minor</button>
                    </div>

                </form>


            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


