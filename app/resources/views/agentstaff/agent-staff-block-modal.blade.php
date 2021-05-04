<!---Place for device register modal-->
<div class="modal fade" data-keyboard="false" data-backdrop="static" id="agent-staff-block-modal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            @if ($staff['Status']=='Y')
                <div class="modal-header alert-danger" style="height:40px;"> BLOCK AGENT STAFF
                    <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
                </div>
            @elseif($staff['Status']=='N')
                <div class="modal-header alert-danger" style="height:40px;"> UNBLOCK AGENT STAFF
                    <button class="close" data-dismiss="modal" style="margin-top:-25px;">&times;</button>
                </div>
            @endif

            <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

            <div id="agent-staff-block" class="modal-body p-3">
                @if ($staff['Status']=='Y')
                    <form id="agent-staff-block-form" method="post" action="{{ action('KYA\AgentStaffController@blockAgentStaff') }}" class="mb-3" novalidate>
                        @csrf
                        <input type="hidden" name="staffId" value="{{ $staff['AgentStaffID']}}">
                        <div class="row">
                            <div class="col-xs-8 col-md-8">
                                <div class="form-group">
                                    <label for="blockReason">Choose reason for blocking this staff</label>
                                    <select class="custom-select" id="blockReason" name="blockReason">
                                        <option value=""> ---------------- Choose reason ----------- </option>
                                        <option value="Involved in Fraudulent activities">Involved in Fraudulent activities</option>
                                        <option value="Not active agent staff">Not active agent staff</option>
                                        <option value="Others –(Specify)">Others – (Specify)</option>
                                    </select>
                                </div>
                            </div>
                        </div>

                        <!--Material textarea-->
                        <div class="form-group">
                            <label for="form7">Reason</label>
                            <textarea name="block-reason-text" id="blockReasonText" class="md-textarea form-control" rows="3"></textarea>
                        </div>

                        <div class="modal-footer">
                            <button id="cancelBlockStaff" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                            <button id="blockStaffBtn" type="submit" class="btn btn-primary">Block Staff</button>
                        </div>
                    </form>
                @elseif($staff['Status']=='N')
                    <form id="agent-staff-unblock-form" method="post" action="{{ action('AgentStaffController@blockAgentStaff') }}" class="mb-3" enctype="multipart/form-data" novalidate>
                        @csrf
                        <input type="hidden" name="staffId" value="{{ $staff['AgentStaffID']}}">
                        <div class="row">
                            <div class="col-xs-8 col-md-8">
                                <div class="form-group">
                                    <label for="unblockReason">Choose reason for blocking this staff</label>
                                    <select class="custom-select" id="unblockReason" name="unblockReason">
                                        <option value="Request for reactivation of service">Request for reactivation of service</option>
                                        <option value="Contract renewal">Contract renewal</option>
                                        {{-- <option value="approved">Approved to be unlocked – Attach reason/ approval document</option> --}}
                                    </select>
                                </div>
                            </div>
                        </div>

                        <!--Material textarea-->
                        {{-- <div class="form-group">
                            <label for="form7">Staff Activating Attachment</label>
                            <div class="col-md-7 col-xs-12 mb-3">
                                <div class="custom-file">
                                    <input type="file" class="form-control-file" name="Unblock-Staff-file" id="unblockstaffFile" aria-describedby="StaffUnblockfileHelp">
                                    <small class="form-text text-muted">Please Attach reason/ approval document</small>
                                </div>
                            </div>
                        </div> --}}

                        <div class="modal-footer">
                            <button id="cancelunBlockStaff" class="btn btn-danger" data-dismiss="modal"> Cancel</button>
                            <button id="unblockStaffBtn" type="submit" class="btn btn-primary">Unblock Staff</button>
                        </div>
                    </form>
                @endif


            </div>

        </div>
    </div>
</div>
<!----end device register modal-->


