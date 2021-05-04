<aside class="aside-container">
    <!-- START Sidebar (left)-->
    <div class="aside-inner">
        <nav class="sidebar" data-sidebar-anyclick-close="">
            <!-- START sidebar nav-->
            <ul class="sidebar-nav">
                <!-- START user info-->
                <li class="has-user-block">
                    <div class="collapse" id="user-block">
                        <div class="item user-block">
                            <!-- User picture-->
                            <div class="user-block-picture">
                                <div class="user-block-status">
                                    <img class="img-thumbnail rounded-circle" src="img/user/02.jpg" alt="Avatar" width="60" height="60">
                                    <div class="circle bg-success circle-lg"></div>
                                </div>
                            </div>
                            <!-- Name and Job-->
                            <div class="user-block-info">
                                <span class="user-block-name">Hello, {Username}</span>
                                <span class="user-block-role">Last logon: 11:14 AM 7/9/2019 &nbsp;<a href='#'><i class="fas fa-sign-out-alt"></i>&nbsp;Logout</a></span>
                                <br />

                                <hr size="5">
                                </hr>
                            </div>
                        </div>
                    </div>
                </li>
                <!-- END user info-->
                <!-- Iterates over all sidebar items-->

                <li class=" ">
                    <a href="#dashboard" title="Dashboard" data-toggle="collapse">
                        <br clear="all/"><br clear="all/">
                        <em class="icon-speedometer"></em>
                        <span active="true">Main Dashboard</span>
                    </a>

                </li>

                <li class="nav-heading ">
                    <span>Bio Registrations</span>
                </li>
                <li class="">
                    <a href="./new_registration.html" title="New registration">
                        <em class="icon-note"></em>
                        <span>New registration</span>
                    </a>

                </li>
                <li class="">
                    <a href="./reregistration.html" title="Re-registration">
                        <em class="icon-doc"></em>
                        <span>Re-registrations</span>
                    </a>

                </li>
                <!----Start of onboarding menu-->
                <li class=" ">
                    <a href="" title="Onboarding" class="">

                        <em class="icon-user"></em>

                        <span>Onboardings</span>

                    </a>
                    <ul class="sidebar-nav sidebar-subnav collapse" id="dashboard">
                        <li class="sidebar-subnav-header">Onboarding</li>
                        <li class="active">
                            <a href="{{ URL::to('list-agents') }}" title="Onboard Agents">
                                <span>Agents</span>
                            </a>
                        </li>
                        <li class=" ">
                            <a href="{{ URL::to('list-agent-staff') }}" title="Onboard Staff Agents">
                                <span>Staffs</span>
                            </a>
                        </li>
                        <li class="">
                            <a href="{{ URL::to('list-devices') }}" title="Onboard Devices">
                                <span>Devices</span>
                            </a>
                        </li>
                    </ul>
                </li>

                <!----End of onboarding menu-->
                <li class="nav-heading ">
                    <span>Reports</span>
                </li>
                <li class="">
                    <a href="./report_generation.html" title="Report generation" <em class="icon-magnifier"></em>
                        <span>Biometric Reports</span>
                    </a>

                </li>
                <!-- <hr size="5" /> -->
                <!---Setting section-->
                <li class="nav-heading ">
                    <span>Settings</span>
                </li>
                <li class="">
                    <a href="#" title="Settings" data-toggle="collapse">
                        <em class="fa fa-cogs"></em>
                        <span>Settings</span>
                    </a>

                </li>
                <!---end of setting section-->
            </ul>
            <!-- END sidebar nav-->
        </nav>
    </div>
    <!-- END Sidebar (left)-->
</aside>