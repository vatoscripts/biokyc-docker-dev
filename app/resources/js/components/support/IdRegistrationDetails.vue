<template>
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-12">
            <div v-show="message" class="text text-danger text-center">
                <span class="lead">{{ message }}</span>
            </div>
            <div class="card b">
                <div class="card-body">
                    <form @submit.prevent="submit" class="mb-3">
                        <div class="align-center">
                            <div class="form-row">
                                <div class="form-group col-4">
                                    <label class="text-bold">ID Number</label>
                                    <input
                                        id="idNumber"
                                        name="idNumber"
                                        class="form-control"
                                        type="text"
                                        placeholder="Enter customer ID number"
                                        v-model="fields.idNumber"
                                    />
                                    <div
                                        v-if="errors && errors.idNumber"
                                        class="text-danger"
                                    >
                                        {{ errors.idNumber[0] }}
                                    </div>
                                </div>

                                <div class="form-group col-4">
                                    <label class="text-bold">REPORT TYPE</label>
                                    <select
                                        class="custom-select"
                                        id="country-select"
                                        name="reportType"
                                        @change="onReportCatChange($event)"
                                    >
                                        <option value>SELECT ONE</option>

                                        <option
                                            v-for="category in categories"
                                            v-bind:value="category.ID"
                                            v-bind:key="category.ID"
                                            >{{ category.Description }}</option
                                        >
                                    </select>
                                    <div
                                        v-if="errors && errors.reportType"
                                        class="text-danger"
                                    >
                                        {{ errors.reportType[0] }}
                                    </div>
                                </div>

                                <div class="form-group col-md-4 col-xs-12">
                                    <button
                                        id="filterRegJourneyDates"
                                        type="submit"
                                        class="btn btn-lg btn-block btn-outline-danger myLead text-bold mt-4"
                                    >
                                        Check
                                    </button>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
            <div v-if="showCustomer">
                <div class="card">
                    <div class="card-body">
                        <div class="row myLead">
                            <div class="col-8">
                                <div class="row mb-2" v-show="showTable">
                                    <div class="col-4 text-monospace">
                                        Customer Name :
                                    </div>
                                    <div class="col-4">
                                        {{ customer.CustomerName }}
                                    </div>
                                </div>
                                <div class="row mb-2">
                                    <div class="col-4 text-monospace">
                                        ID Number :
                                    </div>
                                    <div class="col-4">
                                        {{ customer.IDNumber }}
                                    </div>
                                </div>
                                <div class="row mb-2" v-show="showTable">
                                    <div class="col-4 text-monospace">
                                        Gender :
                                    </div>
                                    <div class="col-4">
                                        {{ customer.Gender }}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="table-responsive" v-if="showTable">
                    <vue-table-dynamic :params="params" ref="table">
                    </vue-table-dynamic>
                </div>
                <div v-if="showSummary">
                    <h3>Customer Registered Msisdn :</h3>
                    <ul>
                        <div
                            v-for="item in customer.DetailedListOfMsisdn"
                            v-bind:key="item.Msisdn"
                        >
                            <li class="lead text-info">{{ item.Msisdn }}</li>
                        </div>
                    </ul>
                </div>
            </div>
        </div>
        <!-- END dashboard main content-->
    </div>
</template>
<script>
import VueTableDynamic from "vue-table-dynamic";

export default {
    components: { VueTableDynamic },
    data() {
        return {
            fields: {},
            errors: {},
            success: false,
            loaded: true,
            loading: false,
            message: null,
            checked: false,
            hasValue: false,
            items: null,
            showCustomer: null,
            showTable: null,
            showSummary: null,
            categories: [
                { ID: "1", Description: "Historical Report" },
                {
                    ID: "2",
                    Description: "Current Report"
                }
            ],
            customer: null,
            params: {
                data: [
                    [
                        "Msisdn",
                        "Agent Name",
                        "Agent Msisdn",
                        "Registration Date",
                        "Platform",
                        "Registration Type"
                    ]
                ],
                header: "row",
                border: true,
                stripe: true,
                pagination: true,
                pageSize: 10,
                sort: [0, 1, 2, 3, 4]
                // pageSizes: [5, 10, 20, 50]
            }
        };
    },
    mounted() {
        this.hasValue = false;
        this.showCustomer = false;
        this.showTable = false;
        this.showSummary = false;
    },
    methods: {
        submit() {
            let loader = this.$loading.show({
                // Optional parameters
                container: this.fullPage ? null : this.$refs.formContainer,
                "is-full-page": true,
                loader: "dots",
                color: "red"
            });

            if (this.loaded) {
                this.loaded = false;
                this.success = false;
                this.errors = {};
                this.message = null;
                this.customer = null;
                this.showCustomer = false;

                axios
                    .post("/api/support/reg-details-id", this.fields)
                    .then(res => {
                        loader.hide();
                        this.showCustomer = true;
                        this.customer = res.data;

                        if (this.fields.reportType == 1) {
                            this.showTable = true;
                            this.showSummary = false;
                            let items = res.data;

                            if (items.DetailedListOfMsisdn.length > 0) {
                                items.DetailedListOfMsisdn.forEach(el => {
                                    this.params.data.push([
                                        el.Msisdn,
                                        el.AgentName,
                                        el.AgentMsisdn,
                                        el.RegistrationDate,
                                        el.RegistrationPlatform,
                                        el.RegistrationType
                                    ]);
                                });
                            } else {
                                this.message =
                                    "Customer details NOT available !";
                            }
                        } else if (this.fields.reportType == 2) {
                            this.showTable = false;
                            this.showSummary = true;
                        }

                        this.loaded = true;
                        // this.success = true;
                        this.loading = false;
                    })
                    .catch(error => {
                        this.loaded = true;
                        loader.hide();

                        if (error.response.status === 422) {
                            this.errors = error.response.data.errors || {};
                        } else if (error.response.status === 400) {
                            this.message = error.response.data.message || {};
                        } else {
                            this.message = "An error has occured !";
                        }
                    });
            }
        },
        onReportCatChange(e) {
            //console.log(response);
            this.fields.reportType = e.target.value;
        }
    }
};
</script>
