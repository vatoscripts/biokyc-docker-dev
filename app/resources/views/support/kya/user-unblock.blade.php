@extends('layout.app')

@section('content')

    <section class="section-container">
        <!-- Page content-->
        <div class="content-wrapper">

            <div class="content-heading">
                <div>Manage User
                    @if (session::get('status')=='Y')
                        <p class="lead mt-2">BLOCK USER</p>
                    @elseif(session::get('status')=='N')
                        <p class="lead mt-2">UNBLOCK USER</p>
                    @endif
                </div>
            </div>

            @include('layout.flash-messages')

            <!-- START cards box-->
            <!-- END cards box-->
            <div class="row">
                <!-- START dashboard main content-->
                <div class="col-xl-12">
                    {{-- <div id="error-message" class="align-center"></div> --}}
                    <blockquote id="flash-message" ></blockquote>
                    <div class="card b">
                        <div class="card-body">
                            <blockquote id="flash-message" class="p-2 text text-danger h4 ml-3"></blockquote>

                            <div id="agent-staff-block" class="modal-body p-3">

                                    <form id="user-unblock-form" method="post" action="{{ action('KYA\AgentStaffController@blockAgentStaff') }}" class="mb-3" enctype="multipart/form-data" novalidate>
                                        @csrf
                                        <input type="hidden" name="userId" value="{{ session::get('userID') }}">
                                        <div class="row">
                                            <div class="col-xs-8 col-md-8">
                                                <div class="form-group">
                                                    <label for="unblockReason">Choose reason for blocking this staff</label>
                                                    <select class="custom-select" id="unblockReason" name="unblockReason">
                                                        <option value=""> ---------------- Choose reason ----------- </option>
                                                        <option value="Request for reactivation of service">Request for reactivation of service</option>
                                                        <option value="Contract renewal">Contract renewal</option>
                                                        {{-- <option value="approved">Approved to be unlocked – Attach reason/ approval document</option> --}}
                                                    </select>
                                                </div>
                                            </div>
                                        </div>

                                        <div class="form-group">
                                            <label for="form7">Reference</label>
                                            <textarea name="unblockReference" class="md-textarea form-control" rows="3" placeholder="Describe the refence for unblocking this user e.g letter, email"></textarea>
                                        </div>

                                        <div class="modal-footer">
                                            <button id="unblockUserBtn" type="submit" class="btn btn-primary">Unblock User</button>
                                        </div>
                                    </form>


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

    <script src="{{ asset('js/user-support/unblock-user.js') }}"></script>

@endsection
