<template>
    <div class="col-10">
        <div class="clearfix"></div>
        <div
            v-show="message"
            class="alert alert-warning alert-block text-center"
        >
            <span class="lead">{{ message }}</span>
        </div>
        <!-- <div v-show="message" class="text text-danger text-center mb-3">
      <span class="h3 lead">{{ message }}</span>
    </div> -->
        <form
            id="diplomatRegisterForm"
            @submit.prevent="submit"
            class="mb-3 p-3"
        >
            <div class="form-row">
                <div class="form-group col-4">
                    <label class="text-bold">First Name</label>
                    <input
                        class="form-control"
                        name="firstName"
                        v-model="fields.firstName"
                    />
                    <div v-if="errors && errors.firstName" class="text-danger">
                        {{ errors.firstName[0] }}
                    </div>
                </div>
                <div class="form-group col-4">
                    <label class="text-bold">Middle Name</label>
                    <input
                        class="form-control"
                        name="middleName"
                        v-model="fields.middleName"
                    />
                    <div v-if="errors && errors.middleName" class="text-danger">
                        {{ errors.middleName[0] }}
                    </div>
                </div>
                <div class="form-group col-4">
                    <label class="text-bold">Last Name</label>
                    <input
                        class="form-control"
                        name="lastName"
                        v-model="fields.lastName"
                    />
                    <div v-if="errors && errors.lastName" class="text-danger">
                        {{ errors.lastName[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group col-4">
                    <label class="text-bold">Diplomat ID Number</label>
                    <input
                        class="form-control"
                        name="idNumber"
                        v-model="fields.idNumber"
                    />
                    <div v-if="errors && errors.idNumber" class="text-danger">
                        {{ errors.idNumber[0] }}
                    </div>
                </div>
                <div class="form-group col-4">
                    <label class="text-bold">DOB</label>
                    <datepicker
                        placeholder="Select Date"
                        input-class="form-control"
                        v-model="fields.dob"
                        name="dob"
                        :disabled-dates="state.disabledDates"
                        :typeable="true"
                    ></datepicker>
                    <div v-if="errors && errors.dob" class="text-danger">
                        {{ errors.dob[0] }}
                    </div>
                </div>
                <div class="form-group col-4">
                    <label class="text-bold">Gender</label>
                    <select
                        class="custom-select text-center"
                        id="gender-select"
                        @change="onGenderChange($event)"
                        name="gender"
                    >
                        <option value>SELECT GENDER</option>
                        <option value="MALE">MALE</option>
                        <option value="FEMALE">FEMALE</option>
                    </select>
                    <div v-if="errors && errors.gender" class="text-danger">
                        {{ errors.gender[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group col-6">
                    <label class="text-bold">Institution Name</label>
                    <input
                        class="form-control"
                        name="institution"
                        v-model="fields.institution"
                    />
                    <div
                        v-if="errors && errors.institution"
                        class="text-danger"
                    >
                        {{ errors.institution[0] }}
                    </div>
                </div>
                <div class="form-group col-6">
                    <label class="text-bold">Country</label>
                    <select
                        class="custom-select text-center"
                        id="country-select"
                        @change="onCountryChange($event)"
                        name="country"
                    >
                        <option value>SELECT COUNTRY</option>

                        <option
                            v-for="country in countries"
                            v-bind:value="country.Code"
                            v-bind:key="country.Code"
                            >{{ country.Name }}</option
                        >
                    </select>
                    <div v-if="errors && errors.country" class="text-danger">
                        {{ errors.country[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group col-6">
                    <label class="font-weight-bold mb-4" for="blockReason"
                        >Reason for additional msisdn</label
                    >
                    <select
                        class="custom-select text-center"
                        id="tcraReason"
                        name="tcraReason"
                        @change="onReasonChange($event)"
                    >
                        <option class value
                            >-------------- Choose reason ------------</option
                        >
                        <option value="1000"
                            >For additional devices (phones, tablets, CCTV,
                            routers etc)</option
                        >
                        <option value="1001"
                            >To separate office and private usage
                        </option>
                        <option value="1002"
                            >To separate business and personal usage</option
                        >
                        <option value="1003"
                            >For mobile financial services</option
                        >
                        <option value="1004"
                            >Mobile number porting - with reasons</option
                        >
                        <option value="1005"
                            >Increase branches/shops or business</option
                        >
                    </select>
                    <div v-if="errors && errors.tcraReason" class="text-danger">
                        {{ errors.tcraReason[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group col-12">
                    <label class="text-bold" for="exampleInputEmail1"
                        >ID Front Picture or Introduction Letter (.PNG OR
                        .JPEG)</label
                    >
                    <input
                        type="file"
                        ref="frontIDFile"
                        class="form-control-file"
                        name="frontIDFile"
                        v-on:change="handleFrontIDFileUpload()"
                        id="customFile"
                    />
                    <div
                        v-if="errors && errors.frontIDFile"
                        class="text-danger"
                    >
                        {{ errors.frontIDFile[0] }}
                    </div>
                </div>
                <div class="form-group col-12">
                    <label class="text-bold"
                        >Diplomat ID Back Picture (.PNG OR .JPEG)</label
                    >
                    <input
                        type="file"
                        ref="backIDFile"
                        class="form-control-file"
                        name="backIDFile"
                        v-on:change="handleBackIDFileUpload()"
                        id="customFile"
                    />
                    <div v-if="errors && errors.backIDFile" class="text-danger">
                        {{ errors.backIDFile[0] }}
                    </div>
                </div>
                <div class="form-group col-12">
                    <label class="text-bold"
                        >Passport Picture (.PNG OR .JPEG)</label
                    >
                    <input
                        type="file"
                        ref="passportFile"
                        class="form-control-file"
                        name="passportFile"
                        v-on:change="handlePassportFileUpload()"
                        id="customFile"
                    />
                    <div
                        v-if="errors && errors.passportFile"
                        class="text-danger"
                    >
                        {{ errors.passportFile[0] }}
                    </div>
                </div>
            </div>

            <button id="bulkRegSave" type="submit" class="btn btn-primary">
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
            countries: null,
            state: {
                date: new Date(),
                disabledDates: {
                    //to: new Date(new Date().getTime() - 6574.365 * 24 * 60 * 60), // Disable all dates up to specific date
                    from: new Date() // Disable all dates after specific date
                }
            }
        };
    },
    mounted() {
        setTimeout(() => {
            axios
                .get("/api/diplomat-countries")
                .then(response => {
                    //console.log(response.data);
                    this.countries = response.data;
                })
                .catch(error => {
                    console.log(error);
                    Toast.fire({
                        icon: "error",
                        title:
                            "An error has occured while fetching countries list !"
                    });
                });
        }, 2000);
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
                .post("/api/diplomat/register-secondary", formData, {
                    headers: {
                        "Content-Type": "multipart/form-data"
                    }
                })
                .then(response => {
                    loader.hide();
                    this.fields = {}; //Clear input fields.

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

                    if (error.response.status === 422) {
                        this.errors = error.response.data.errors || {};
                    } else if (error.response.status === 400) {
                        this.message =
                            "Error: " + error.response.data.message || {};
                    } else {
                        Toast.fire({
                            icon: "error",
                            title: "An error has occured !"
                        });
                    }
                });
        },

        handleFrontIDFileUpload() {
            this.fields.frontIDFile = this.$refs.frontIDFile.files[0];
        },
        handleBackIDFileUpload() {
            this.fields.backIDFile = this.$refs.backIDFile.files[0];
        },

        handlePassportFileUpload() {
            this.fields.passportFile = this.$refs.passportFile.files[0];
        },

        onGenderChange(e) {
            //console.log(response);
            this.fields.gender = e.target.value;
        },
        onCountryChange(e) {
            this.fields.country = e.target.value;
        },
        onReasonChange(e) {
            this.fields.tcraReason = e.target.value;
        }
    }
};
</script>
