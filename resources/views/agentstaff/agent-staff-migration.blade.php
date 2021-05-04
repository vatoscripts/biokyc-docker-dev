@extends('layout.app')

@section('content')

<!-- Main section-->
<section class="section-container">
    <!-- Page content-->
    <div class="content-wrapper">
        <div class="content-heading">
            <div>Staff Migration
                <p class="lead mt-2">KYA Reports: Migrate Staff from one Agent to another.</p>
            </div>
        </div>
        @include('layout.flash-messages')

        <form method="post" action="{{ action('AgentStaffController@staffMigrate') }}" class="mb-3" id="agentToForm" novalidate>
            @csrf
            <div class="card">
                <div class="card-body">
                    <div class="form-row">
                        <div class="form-group col-5">
                            <label for=""><strong>Choose Donor Agent</strong></label>
                            <select name="agentFrom" class="form-control" onchange="getAgents()" id="agentFrom-dropdown">

                            </select>
                        </div>
                        <div class="form-group col-5">
                            <button id="agentFromBtn" type="submit" class="btn btn-lg btn-outline-danger text-bold mt-4">Load Staff</button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card" id="agent-staff-migration-list-wrapper">
                <div class="card-body">
                    <div id="agent-staff-migration-list">
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-body">
                    <div class="form-row">
                        <div class="form-group col-md-12">
                            <label for="form7"><strong>Reason for Migrating these staff</strong></label>
                            <textarea name="staff-migration-reason" id="form7" class="md-textarea form-control" rows="2"></textarea>
                        </div>
                        <div class="form-group col-5">
                            <label for=""><strong>Choose Recepient Agent</strong></label>
                            <select name="agentTo" class="form-control"  id="agentTo-dropdown">
                            </select>
                        </div>
                    </div>
                    <button id="agentToBtn" type="submit" class="btn btn-lg btn-outline-danger text-bold">Migrate Staff</button>
                </div>
            </div>
        </form>

    </div>
</section>

@endsection

@section('scripts')

    <script src="{{ asset('js/agentstaff-migration.js') }}"></script>

@endsection
