<template>
    <div class="col-8">
        <div class="clearfix"></div>
        <div
            v-show="message"
            class="alert alert-warning alert-block text-center"
        >
            <span class="h4 lead">{{ message }}</span>
        </div>
        <form id="bulkRegSaveForm" @submit.prevent="submit" class="mb-3 p-3">
            <div class="row">
                <div class="col-6 mb-3">
                    <label class="text-bold" for="exampleInputEmail1"
                        >Is Machine-to-Machine ?
                    </label>
                    <select
                        class="custom-select"
                        id="machine2machine"
                        name="machine2machine"
                        @change="onM2MChange($event)"
                    >
                        <option value=""> -- Choose One --</option>
                        <option value="Y">YES</option>
                        <option value="N">NO</option>
                    </select>
                    <div
                        v-if="errors && errors.machine2machine"
                        class="text-danger"
                    >
                        {{ errors.machine2machine[0] }}
                    </div>
                </div>

                <div class="col-6">
                    <label class="text-bold" for="registrationCategory"
                        >Registration Category</label
                    >

                    <select
                        class="custom-select"
                        name="registrationCategory"
                        @change="onRegistrationCategoryChange($event)"
                    >
                        <option value="">-- Choose One --</option>
                        <option
                            v-for="category in categories"
                            v-bind:value="category.ID"
                            v-bind:key="category.ID"
                            >{{ category.Description }}</option
                        >
                    </select>

                    <div
                        v-if="errors && errors.registrationCategory"
                        class="text-danger"
                    >
                        {{ errors.registrationCategory[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row mb-3">
                <div class="col-6 ">
                    <label class="text-bold"
                        >Company/Institution Email address</label
                    >
                    <input
                        name="companyEmail"
                        type="email"
                        class="form-control"
                        id="company-email"
                        placeholder="Enter email"
                        v-model="fields.companyEmail"
                    />
                    <div
                        v-if="errors && errors.companyEmail"
                        class="text-danger"
                    >
                        {{ errors.companyEmail[0] }}
                    </div>
                </div>
                <div class="col-6">
                    <label class="text-bold">Company Registration Date</label>
                    <datepicker
                        placeholder="Select Company Registration Date"
                        input-class="form-control"
                        v-model="fields.companyRegDate"
                        name="minorDOB"
                        :disabled-dates="state.disabledDates"
                        :typeable="true"
                    >
                        ></datepicker
                    >
                    <div
                        v-if="errors && errors.companyRegDate"
                        class="text-danger"
                    >
                        {{ errors.companyRegDate[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row" id="SPOCAttachment" v-if="showSPOCAttachment">
                <div class="col-md-7 col-xs-12 mb-3">
                    <label class="text-bold" for="exampleInputEmail1"
                        >Institution Introduction Letter</label
                    >
                    <div class="custom-file">
                        <input
                            type="file"
                            ref="SPOCFile"
                            class="form-control-file"
                            name="spocAttachmentFile"
                            id="spoc-attachment-file"
                            v-on:change="handleSpocFileUpload()"
                        />
                        <div
                            v-if="errors && errors.spocAttachmentFile"
                            class="text-danger"
                        >
                            {{ errors.spocAttachmentFile[0] }}
                        </div>
                    </div>
                </div>
            </div>

            <div class="form-row  mb-3" v-if="showTINBlock">
                <div class="col-4">
                    <label class="text-bold">TIN Certificate</label>
                    <div class="custom-file">
                        <input
                            type="file"
                            ref="TINFile"
                            class="form-control-file"
                            name="TIN-file"
                            id="TIN-file"
                            v-on:change="handleTINFileUpload()"
                        />
                        <div
                            v-if="errors && errors.TINFile"
                            class="text-danger"
                        >
                            {{ errors.TINFile[0] }}
                        </div>
                    </div>
                </div>

                <div class="col-4">
                    <label class="text-bold">TIN Number</label>
                    <input
                        name="TIN"
                        type="text"
                        class="form-control"
                        id="TIN"
                        placeholder="TIN"
                        v-model="fields.TIN"
                    />
                    <div v-if="errors && errors.TIN" class="text-danger">
                        {{ errors.TIN[0] }}
                    </div>
                </div>
                <div class="col-4">
                    <label class="text-bold">TIN Registration Date</label>
                    <datepicker
                        placeholder="Select TIN Registration Date"
                        input-class="form-control"
                        v-model="fields.tinDate"
                        name="minorDOB"
                        :disabled-dates="state.disabledDates"
                        :typeable="true"
                    ></datepicker>
                    <div v-if="errors && errors.tinDate" class="text-danger">
                        {{ errors.tinDate[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row mb-3" v-if="showLicenceBlock">
                <div class="col-6">
                    <label class="text-bold" for="exampleInputEmail1"
                        >Business Licence Document</label
                    >

                    <div class="custom-file">
                        <input
                            type="file"
                            class="form-control-file"
                            ref="businessLicenceFile"
                            name="business-licence-file"
                            id="business-licence-file"
                            v-on:change="handleLicenceFileUpload()"
                        />
                        <div
                            v-if="errors && errors.businessLicenceFile"
                            class="text-danger"
                        >
                            {{ errors.businessLicenceFile[0] }}
                        </div>
                    </div>
                </div>

                <div class="col-6">
                    <label class="text-bold" for="exampleInputEmail1"
                        >Business Licence Number</label
                    >

                    <input
                        name="business-licence"
                        type="text"
                        class="form-control"
                        id="business-licence"
                        placeholder="Business Licence Number"
                        v-model="fields.businessLicence"
                    />
                    <div
                        v-if="errors && errors.businessLicence"
                        class="text-danger"
                    >
                        {{ errors.businessLicence[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row mb-3" v-if="showBrelaBlock">
                <div class="col-4">
                    <label class="text-bold" for="exampleInputEmail1"
                        >Certificate of Incorporation (BRELA)</label
                    >
                    <div class="custom-file">
                        <input
                            type="file"
                            ref="brelaFile"
                            class="form-control-file"
                            name="brelaFile"
                            id="BRELA-file"
                            v-on:change="handleBrelaFileUpload()"
                        />
                        <div
                            v-if="errors && errors.brelaFile"
                            class="text-danger"
                        >
                            {{ errors.brelaFile[0] }}
                        </div>
                    </div>
                </div>

                <div class="col-4 ">
                    <label class="text-bold"
                        >Certificate of Incorporation Number</label
                    >
                    <input
                        name="companyEmail"
                        type="text"
                        class="form-control"
                        id="brela-number"
                        placeholder="Enter Incorporation Number"
                        v-model="fields.brelaNumber"
                    />
                    <div
                        v-if="errors && errors.brelaNumber"
                        class="text-danger"
                    >
                        {{ errors.brelaNumber[0] }}
                    </div>
                </div>

                <div class="col-4">
                    <label class="text-bold"
                        >Certificate of Incorporation Date</label
                    >
                    <datepicker
                        placeholder="Select Incorporation Date"
                        input-class="form-control"
                        v-model="fields.brelaDate"
                        name="minorDOB"
                        :disabled-dates="state.disabledDates"
                        :typeable="true"
                    ></datepicker>
                    <div v-if="errors && errors.brelaDate" class="text-danger">
                        {{ errors.brelaDate[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row mb-3" v-if="showRegCertBlock">
                <div class="col-4">
                    <label class="text-bold" for="exampleInputEmail1"
                        >Certificate of Incorporation (BRELA)</label
                    >
                    <div class="custom-file">
                        <input
                            type="file"
                            ref="brelaFile"
                            class="form-control-file"
                            name="brelaFile"
                            id="BRELA-file"
                            v-on:change="handleBrelaFileUpload()"
                        />
                        <div
                            v-if="errors && errors.brelaFile"
                            class="text-danger"
                        >
                            {{ errors.brelaFile[0] }}
                        </div>
                    </div>
                </div>

                <div class="col-4">
                    <label class="text-bold"
                        >Certificate of Registration Number</label
                    >
                    <input
                        name="companyEmail"
                        type="text"
                        class="form-control"
                        id="cert-registration-number"
                        placeholder="Enter Certificate of Registration Number"
                        v-model="fields.regCertNumber"
                    />
                    <div
                        v-if="errors && errors.regCertNumber"
                        class="text-danger"
                    >
                        {{ errors.regCertNumber[0] }}
                    </div>
                </div>

                <div class="col-4">
                    <label class="text-bold"
                        >Certificate of Registration Date</label
                    >
                    <datepicker
                        placeholder="Select Certificate of Registration Date"
                        input-class="form-control"
                        v-model="fields.regCertDate"
                        name="minorDOB"
                        :disabled-dates="state.disabledDates"
                        :typeable="true"
                    ></datepicker>
                    <div
                        v-if="errors && errors.regCertDate"
                        class="text-danger"
                    >
                        {{ errors.regCertDate[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row">
                <div class="col-md-7 col-xs-12 mb-3">
                    <label class="text-bold" for="exampleInputEmail1"
                        >MSISDN Attachment</label
                    >
                    <div class="custom-file">
                        <input
                            type="file"
                            ref="msisdnFile"
                            class="form-control-file"
                            name="msisdnFile"
                            v-on:change="handleMsisdnFileUpload()"
                        />
                        <div
                            v-if="errors && errors.msisdnFile"
                            class="text-danger"
                        >
                            {{ errors.msisdnFile[0] }}
                        </div>
                    </div>
                </div>
            </div>

            <button
                id="bulkRegSave"
                type="submit"
                class="btn btn-lg btn-block btn-outline-danger myLead"
            >
                Register
            </button>
        </form>
    </div>
</template>
<script>
import Datepicker from "vuejs-datepicker/dist/vuejs-datepicker.esm.js";

export default {
    components: {
        Datepicker
    },
    data() {
        return {
            fields: {},
            errors: {},
            success: false,
            loaded: true,
            loading: true,
            message: null,
            TINFile: "",
            businessLicenceFile: "",
            zones: null,
            zoneID: null,
            regions: null,
            region: null,
            territories: null,
            showSPOCAttachment: false,
            showTINBlock: false,
            showBrelaBlock: false,
            showLicenceBlock: false,
            showRegCertBlock: false,
            categories: [
                {
                    ID: "COMP_I",
                    Description: "Company SIM (Incorporation Certificate)"
                },
                {
                    ID: "COMP_R",
                    Description: "Company SIM (Registration Certificate)"
                },
                {
                    ID: "INST",
                    Description: "Institution SIM Card Registration"
                }
                // {
                //     ID: "CEMP",
                //     Description: "Company Employees SIM Card Registration"
                // }
            ],
            state: {
                date: new Date(),
                disabledDates: {
                    //to: new Date(new Date().getTime() - 6574.365 * 24 * 60 * 60), // Disable all dates up to specific date
                    from: new Date() // Disable all dates after specific date
                }
            }
        };
    },

    methods: {
        submit() {
            this.errors = {};
            this.message = null;

            let loader = this.$loading.show({
                // Optional parameters
                container: this.fullPage ? null : this.$refs.formContainer,
                "is-full-page": true,
                loader: "dots",
                color: "red"
            });

            let formData = new FormData();

            for (var key in this.fields) {
                formData.append(key, this.fields[key]);
            }

            axios
                .post("/api/one-sim/bulk/primary-register", formData, {
                    headers: {
                        "Content-Type": "multipart/form-data"
                    }
                })
                .then(response => {
                    loader.hide();
                    // this.fields = {}; //Clear input fields.

                    Swal.fire({
                        icon: "success",
                        title: "Success",
                        text: response.data.message
                    }).then(() => {
                        window.location = "/home";
                    });
                })
                .catch(error => {
                    this.loaded = true;
                    loader.hide();
                    console.log(error);
                    if (error.response.status === 422) {
                        this.errors = error.response.data.errors || {};
                    } else if (error.response.status === 400) {
                        this.message = error.response.data.message || {};
                    } else {
                        this.message = "An error has occured !";
                    }
                });
        },

        handleSpocFileUpload() {
            this.fields.spocAttachmentFile = this.$refs.SPOCFile.files[0];
        },
        handleTINFileUpload() {
            this.fields.TINFile = this.$refs.TINFile.files[0];
        },

        handleLicenceFileUpload() {
            this.fields.businessLicenceFile = this.$refs.businessLicenceFile.files[0];
        },

        handleBrelaFileUpload() {
            this.fields.brelaFile = this.$refs.brelaFile.files[0];
        },

        handleMsisdnFileUpload() {
            this.fields.msisdnFile = this.$refs.msisdnFile.files[0];
        },

        onRegistrationCategoryChange(event) {
            this.fields.registrationCategory = event.target.value;
            if (event.target.value == "COMP_I") {
                this.showSPOCAttachment = false;
                this.showTINBlock = true;
                this.showLicenceBlock = true;
                this.showBrelaBlock = true;
                this.showRegCertBlock = false;
            } else if (event.target.value == "COMP_R") {
                this.showSPOCAttachment = false;
                this.showLicenceBlock = true;
                this.showTINBlock = true;
                this.showRegCertBlock = true;
                this.showBrelaBlock = false;
            } else if (event.target.value == "INST") {
                this.showSPOCAttachment = true;
                this.showLicenceBlock = false;
                this.showBrelaBlock = false;
                this.showTINBlock = false;
                this.showRegCertBlock = false;
            } else if (event.target.value == "CEMP") {
                this.showTINBlock = true;
                this.showSPOCAttachment = false;
                this.showLicenceBlock = true;
                this.showBrelaBlock = true;
                this.showRegCertBlock = false;
            }
        },
        onM2MChange(e) {
            this.fields.machine2machine = e.target.value;
        },
        customFormatter(date) {
            return moment(date).format("MMMM Do YYYY, h:mm:ss a");
        }
    }
};
</script>
