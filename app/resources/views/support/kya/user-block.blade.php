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

                                        <form id="user-block-form" method="post" action="{{ action('Support\KYASupportController@blockUser') }}" class="mb-3" novalidate>
                                            @csrf
                                            <input type="hidden" name="userId" value="{{ session::get('userID') }}">
                                            <div class="row">
                                                <div class="col-xs-8 col-md-8">
                                                    <div class="form-group">
                                                        <label for="blockReason">Choose reason for blocking this staff</label>
                                                        <select class="custom-select" id="blockReason" name="blockReason">
                                                            <option value=""> ---------------- Choose reason ----------- </option>
                                                            <option value="Involved in Fraudulent activities">Involved in Fraudulent activities</option>
                                                            <option value="Not active agent staff">Not active agent staff</option>
                                                            <option value="Wrongly onboarded">Wrongly onboarded</option>
                                                            <option value="Termination of contract/employment">Termination of contract/employment</option>
                                                            <option value="Others –(Specify)">Others – (Specify)</option>
                                                        </select>
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="form-group">
                                                <label for="form7">Reference</label>
                                                <textarea name="blockReference" class="md-textarea form-control" rows="3" placeholder="Describe the refence for blocking this user e.g letter, email !"></textarea>
                                            </div>

                                            <!--Material textarea-->
                                            <div class="form-group" id="blockReasonText">
                                                <label for="form7">Reason</label>
                                                <textarea name="block-reason-text" class="md-textarea form-control" rows="3"></textarea>
                                            </div>

                                            <div class="modal-footer">
                                                <button id="blockUserBtn" type="submit" class="btn btn-primary">Block User</button>
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

    <script src="{{ asset('js/user-support/block-user.js') }}"></script>

@endsection
