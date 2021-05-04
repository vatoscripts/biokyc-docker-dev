@isset($user)
    <nav class="sidebar" data-sidebar-anyclick-close="">
        <!-- START sidebar nav-->
        <ul class="sidebar-nav">
            <li class="nav-heading "><span data-localize="sidebar.heading.HEADER">Main Navigation</span></li>

            <li class="">
                <a href="/home" title="Dashboard">
                    <em class="icon-speedometer"></em><span data-localize="sidebar.nav.DASHBOARD">Dashboard</span>
                </a>
            </li>
			@if ($user['Role'] === 1 || $user['Role'] === 7 || $user['Role'] === 11)
				<li class=" "><a href="#layout" title="Layouts" data-toggle="collapse"><em class="icon-layers"></em><span>Bio Registrations</span></a>
					<ul class="sidebar-nav sidebar-subnav collapse" id="layout">
                        <li class="sidebar-subnav-header">Bio Registrations</li>
                        <li><a href="/one-sim/new-reg" title="Register new SIM"><span>New Registration</span></a></li>
						{{-- <li class=" "><a href="/new-registration" title="new-registration"><span>New Registrations</span></a></li> --}}
						<li><a href="/re-registration" title="re-registration"><span>Re-Registrations</span></a></li>
						<li><a href="/sim-swap-registration" title="sim-swap-registration"><span>SIM Swap</span></a></li>
                        {{-- <li class=" "><a href="/foreigner-registration" title="foreigner-registration"><span>Foreigner New Registration</span></a></li> --}}
                        <li><a href="/one-sim/visitor/new-reg" title="foreigner-registration"><span>Visitor Registration</span></a></li>
						<li><a href="/foreigner-re-registration" title="foreigner-re-registration"><span>Foreigner Re-Registration</span></a></li>
						<li><a href="/de-registration/nida" title="De-registration"><span>De-Registration</span></a></li>
						@if ($user['Role'] === 7)
                            {{-- <li><a href="/bulk-registration" title="bulk-registration"><span>Bulk Registration</span></a></li> --}}
                            <li><a href="/one-sim/bulk/new-reg" title="bulk-registration"><span>Bulk Registration</span></a></li>

                        <li><a href="/one-sim/minor" title="Minor-registration"><span>Minor Registration</span></a></li>
                        @endif
					</ul>
				</li>
                @if ($user['Role'] === 7)
                <li class=" "><a href="#Diplomats" title="Layouts" data-toggle="collapse"><em class="icon-note"></em><span>Diplomats</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="Diplomats">
                        <li class="sidebar-subnav-header">Diplomats</li>
                            {{-- <li class=" "><a href="/diplomat-registration" title="diplomat-registration-individual"><span>Individual Registration</span></a></li> --}}
                            <li class=" "><a href="/one-sim/diplomat/new-reg" title="diplomat-registration-individual"><span>Individual Registration</span></a></li>
                            <li class=" "><a href="/diplomat-registration-bulk" title="diplomat-registration-individual"><span>Bulk Registration</span></a></li>
                    </ul>
                </li>
                @endif

                <li class=" "><a href="#OneSIM" title="Layouts" data-toggle="collapse"><em class="icon-grid"></em><span>SIM Declaration</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="OneSIM">
                        <li class="sidebar-subnav-header">SIM Declaration</li>
                        <li class=" "><a href="/one-sim/primary/start" title="Set Primary SIM"><span>Primary SIM</span></a></li>
                        <li class=" "><a href="/one-sim/secondary/start" title="Set Secondary SIM"><span>Secondary SIM</span></a></li>
                        {{-- <li class=" "><a href="/one-sim/bulk-declaration/start" title="Set Secondary SIM"><span>Bulk Declaration</span></a></li> --}}
						{{-- <li class=" "><a href="/primary-sim-first" title="Set Primary SIM(NIDA)"><span>Primary SIM NIDA</span></a></li> --}}
                        {{-- <li class=" "><a href="/secondary-sim-first" title="Set Secondary SIM(NIDA)"><span>Secondary SIM NIDA</span></a></li>
                        <li class=" "><a href="/primary-sim/other/first" title="Set Primary SIM(Other)"><span>Primary SIM Other</span></a></li>
                        <li class=" "><a href="/secondary-sim/other/first" title="Set Secondary SIM(Other)"><span>Secondary SIM Other</span></a></li> --}}
                    </ul>
                </li>

            @endif

			@if ($user['Role'] === 3)
                <li class=" "><a href="#Onboardings" title="Layouts" data-toggle="collapse"><em class="icon-note"></em><span>Onboarding</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="Onboardings">
                        <li class="sidebar-subnav-header">Onboardings</li>
						<li class=" "><a href="/agent-staff" title="re-registration"><span>Agent Staff</span></a></li>
						<li class=" "><a href="/agent-staff-recruiter" title="Agent Staff Recruiter"><span>Agent Staff Recruiter</span></a></li>
                    </ul>
                </li>
            @endif

            @if ($user['Role'] === 4)
                <li class=" "><a href="#Onboardings" title="Layouts" data-toggle="collapse"><em class="icon-note"></em><span>Onboarding</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="Onboardings">
                        <li class="sidebar-subnav-header">Onboardings</li>
						<li class=" "><a href="/agent-staff" title="re-registration"><span>Agent Staff</span></a></li>
                    </ul>
                </li>
            @endif

            @if ($user['Role'] === 5)
                <li class=" "><a href="#Onboardings" title="Layouts" data-toggle="collapse"><em class="icon-note"></em><span>Onboarding</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="Onboardings">
                        <li class="sidebar-subnav-header">Onboardings</li>
                        <li class=" "><a href="/agents" title="new-registration"><span>Agents</span></a></li>
                    </ul>
                </li>
            @endif

            @if ($user['Role'] === 8 || $user['Role'] === 5 || $user['Role'] === 9 || $user['Role'] === 12)
                <li class=" "><a href="#Support" title="Layouts" data-toggle="collapse"><em class="icon-note"></em><span>Support</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="Support">
                        <li class="sidebar-subnav-header">Agent Staff</li>
                        <li class=" "><a href="/support/agent-staff-details" title="kyc-reports"><span>Agent Staff Details</span></a></li>
                        <li class=" "><a href="/support/customer-reg-details" title="kyc-reports"><span>Customer Details </span></a></li>
                        <li class=" "><a href="/support/customer-reg-details/id" title="kyc-reports"><span>Registration Details </span></a></li>
                        @if ($user['Role'] === 9)
                            <li class=" "><a href="/support/user-details" title="kyc-reports"><span>User Management </span></a></li>
                        @endif
                        @if ($user['Role'] === 12)
                        <li class=" "><a href="/support/alternative-visitors" title="alternative-visitors"><span>Alternative Visitors </span></a></li>
                        @endif
                    </ul>
                </li>
            @endif

			@if ($user['Role'] === 2)
                <li class=" "><a href="#Onboardings" title="Layouts" data-toggle="collapse"><em class="icon-note"></em><span>Onboarding</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="Onboardings">
                        <li class="sidebar-subnav-header">Onboardings</li>
                        <li class=" "><a href="/agents" title="new-registration"><span>Agents</span></a></li>
                    </ul>
                </li>

				<li class="">
					<a href="/list-users" title="View All Users">
						<em class="icon-speedometer"></em><span data-localize="sidebar.nav.DASHBOARD">List Users</span>
					</a>
				</li>

                <li class=" "><a href="#Support" title="Layouts" data-toggle="collapse"><em class="icon-note"></em><span>Support</span></a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="Support">
                        <li class="sidebar-subnav-header">Agent Staff</li>
                        <li class=" "><a href="/support/agent-staff-details" title="kyc-reports"><span>Agent Staff Details</span></a></li>
                        <li class=" "><a href="/support/customer-reg-details" title="kyc-reports"><span>Customer Details </span></a></li>
                        <li class=" "><a href="/support/customer-reg-details/id" title="kyc-reports"><span>Registration Details </span></a></li>
                        <li class=" "><a href="/support/user-details" title="kyc-reports"><span>User Management </span></a></li>
                        <li class=" "><a href="/support/alternative-visitors" title="alternative-visitors"><span>Alternative Visitors </span></a></li>
                    </ul>
                </li>

            @endif

            @if ($user['Role'] === 2 || $user['Role'] === 5 || $user['Role'] === 9))
            <li class=""><a href="#extras" title="Extras" data-toggle="collapse"><em class="icon-pie-chart"></em><span data-localize="sidebar.nav.extra.EXTRA">Reports</span></a>
                <ul class="sidebar-nav sidebar-subnav collapse" id="extras">
                    <li class="sidebar-subnav-header">Reports</li>
                    <li class=" "><a href="/reports/kyc" title="kyc-reports"><span>KYC </span></a></li>
                </ul>
            </li>

            @endif

        </ul><!-- END sidebar nav-->
    </nav>

@endisset
