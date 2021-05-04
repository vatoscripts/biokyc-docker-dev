<template>
    <div class="col-8">
        <div class="clearfix"></div>
        <div
            v-show="message"
            class="alert alert-danger alert-block mt-1 text-center"
        >
            <button type="button" class="close" data-dismiss="alert">×</button>
            <span class="lead">{{ message }}</span>
        </div>
        <form @submit.prevent="submit" class="mb-3">
            <div class="form-row">
                <div class="col-4 col-xs-12 mb-3">
                    <label class="text-bold">First Name</label>
                    <input
                        name="firstName"
                        type="text"
                        class="form-control"
                        id="first-name"
                        placeholder="Enter minor first name"
                        v-model="fields.firstName"
                    />
                    <div v-if="errors && errors.firstName" class="text-danger">
                        {{ errors.firstName[0] }}
                    </div>
                </div>
                <div class="col-4 col-xs-12 mb-3">
                    <label class="text-bold">Middle Name</label>
                    <input
                        name="middleName"
                        type="text"
                        class="form-control"
                        id="middle-name"
                        placeholder="Enter minor middle name"
                        v-model="fields.middleName"
                    />
                    <div v-if="errors && errors.middleName" class="text-danger">
                        {{ errors.middleName[0] }}
                    </div>
                </div>
                <div class="col-4 col-xs-12 mb-3">
                    <label class="text-bold">Last Name</label>
                    <input
                        name="parentMsisdn"
                        type="text"
                        class="form-control"
                        id="parent-msisdn"
                        placeholder="Enter minor last name"
                        v-model="fields.lastName"
                    />
                    <div v-if="errors && errors.lastName" class="text-danger">
                        {{ errors.lastName[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row"></div>

            <div class="row">
                <div class="form-group col-6">
                    <label class="text-bold">Minor Gender</label>

                    <select
                        class="custom-select"
                        id="gender"
                        name="gender"
                        v-model="fields.minorGender"
                        @change="onMinorGenderChange($event)"
                    >
                        <option value>SELECT GENDER</option>
                        <option value="MALE">MALE</option>
                        <option value="FEMALE">FEMALE</option>
                    </select>

                    <div
                        v-if="errors && errors.minorGender"
                        class="text-danger"
                    >
                        {{ errors.minorGender[0] }}
                    </div>
                </div>
                <div class="form-group col-6">
                    <label class="text-bold">Minor DOB</label>
                    <datepicker
                        placeholder="Select Date"
                        input-class="form-control"
                        v-model="fields.minorDOB"
                        name="minorDOB"
                        :disabled-dates="state.disabledDates"
                        :typeable="true"
                    ></datepicker>
                    <div v-if="errors && errors.minorDOB" class="text-danger">
                        {{ errors.minorDOB[0] }}
                    </div>
                </div>
            </div>

            <div class="form-row">
                <div class="col-4">
                    <div class="form-group">
                        <label class="text-bold"
                            >Birth Certicate/Passport Number</label
                        >

                        <input
                            name="idNumber"
                            type="text"
                            class="form-control"
                            id="idNumber"
                            placeholder="Enter birth certificate/passport no..."
                            v-model="fields.idNumber"
                        />
                        <div
                            v-if="errors && errors.idNumber"
                            class="text-danger"
                        >
                            {{ errors.idNumber[0] }}
                        </div>
                    </div>
                </div>

                <div class="col-4">
                    <div class="form-group">
                        <label class="text-bold"
                            >Birth Certificate/Passport file</label
                        >
                        <div class="custom-file p-2">
                            <input
                                type="file"
                                ref="IDFile"
                                class="form-control-file"
                                name="ID-file"
                                id="ID-file"
                                v-on:change="handleIDFileUpload()"
                            />
                            <div
                                v-if="errors && errors.IDFile"
                                class="text-danger"
                            >
                                {{ errors.IDFile[0] }}
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-4">
                    <div class="form-group">
                        <label class="text-bold">Potrait photo file</label>
                        <div class="custom-file p-2">
                            <input
                                type="file"
                                ref="potraitFile"
                                class="form-control-file"
                                name="potrait-file"
                                id="potrait-file"
                                v-on:change="handlePotraitFileUpload()"
                            />
                            <div
                                v-if="errors && errors.potraitFile"
                                class="text-danger"
                            >
                                {{ errors.potraitFile[0] }}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- <div class="form-row">
        <div class="col-md-12 col-xs-12 mb-3">
          <label class="text-bold">Minor nationality</label>
          <select
            class="custom-select"
            id="country-select"
            name="country"
            @change="onMinorCountryChange($event)"
          >
            <option value>SELECT COUNTRY</option>

            <option
              v-for="country in countries"
              v-bind:value="country.Code"
              v-bind:key="country.Code"
            >{{ country.Name }}</option>
          </select>
          <div
            v-if="errors && errors.minorNationality"
            class="text-danger"
          >{{ errors.minorNationality[0] }}</div>
        </div>
      </div>-->

            <div class="form-row">
                <div class="col-md-12 col-xs-12 mb-3">
                    <label class="text-bold">Parent/Guardian msisdn</label>
                    <input
                        name="parentMsisdn"
                        value
                        type="text"
                        class="form-control"
                        id="parent-msisdn"
                        placeholder="Enter parent MSISDN e.g 0754xxxxxx"
                        v-model="fields.parentMsisdn"
                    />
                    <div
                        v-if="errors && errors.parentMsisdn"
                        class="text-danger"
                    >
                        {{ errors.parentMsisdn[0] }}
                    </div>
                </div>
            </div>

            <div class="form-group">
                <label class="text-bold">Parent/Guardian NIDA number</label>
                <input
                    id="parentNIN"
                    name="parentNIN"
                    class="form-control"
                    type="text"
                    placeholder="Enter NIDA number"
                    v-model="fields.parentNIN"
                />
                <div v-if="errors && errors.parentNIN" class="text-danger">
                    {{ errors.parentNIN[0] }}
                </div>
            </div>

            <input type="hidden" name="fingerData" id="fingerData" />
            <input type="hidden" name="fingerCode" id="fingerCode" />

            <div class="row">
                <div class="col-6">
                    <div v-if="errors && errors.fingerCode" class="text-danger">
                        {{ errors.fingerCode[0] }}
                    </div>
                </div>
                <div class="col-6">
                    <div v-if="errors && errors.fingerData" class="text-danger">
                        {{ errors.fingerData[0] }}
                    </div>
                </div>
            </div>

            <div style="margin: 6em;">
                <table>
                    <tr valign="top">
                        <td>
                            <div class="backgroundA">
                                <input
                                    id="Radio1"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    type="radio"
                                    style="position: absolute; top: 49px; left: -9px;"
                                />
                                <input
                                    id="Radio2"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="
                    position: absolute;
                    top: -4px;
                    left: 35px;
                    height: 20px;
                  "
                                />
                                <input
                                    id="Radio3"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position: absolute; top: -17px; left: 95px;"
                                />
                                <input
                                    id="Radio4"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position: absolute; top: -1px; left: 164px;"
                                />
                                <input
                                    id="Radio5"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position: absolute; top: 125px; left: 219px;"
                                />
                                <input
                                    id="Radio6"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="
                    position: absolute;
                    top: 125px;
                    left: 259px;
                    width: 20px;
                  "
                                />
                                <input
                                    id="Radio7"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position: absolute; top: -1px; left: 315px;"
                                />
                                <input
                                    id="Radio8"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position: absolute; top: -17px; left: 381px;"
                                />
                                <input
                                    id="Radio9"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position: absolute; top: 0px; left: 446px;"
                                />
                                <input
                                    id="Radio10"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="
                    position: absolute;
                    top: 45px;
                    left: 485px;
                    height: 20px;
                  "
                                />
                                <div
                                    id="lblCapture"
                                    style="position: absolute; top: 200px; left: 218px;"
                                >
                                    <b>Select Finger</b>
                                </div>
                                <input
                                    id="Button1"
                                    type="button"
                                    value="Capture Fingerprint"
                                    class="btn btn-danger"
                                    onclick="Capture()"
                                    style="position: relative; top: 229px; left: 190px;"
                                />
                            </div>
                        </td>
                        <td style="padding: 10px;">
                            <div class="row">
                                <div
                                    class="col-sm-12"
                                    style="margin-bottom: 10px;"
                                >
                                    <img
                                        id="FingerImage"
                                        src=" "
                                        style="
                      height: 130px;
                      min-width: 140px;
                      border: solid 1px #cccccc;
                    "
                                    />
                                </div>
                            </div>
                            <div class="row">
                                <div class="col-sm-12">
                                    <input
                                        id="Button1"
                                        type="button"
                                        value="Reset Fingerprint"
                                        class="btn btn-default"
                                        onclick="ResetCaptureImage()"
                                    />
                                </div>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>

            <button
                id="sendAggregatorNIDA"
                type="submit"
                class="btn btn-lg btn-primary"
            >
                <em class="fa mr-2 fas fa-arrow-right"></em> Register
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
            selectedFinger: "Select Finger",
            FingerImage: null,
            regions: null,
            districts: null,
            wards: null,
            villages: null,
            countries: null,
            state: {
                date: new Date(),
                disabledDates: {
                    //to: new Date(new Date().getTime() - 6574.365 * 24 * 60 * 60), // Disable all dates up to specific date
                    from: new Date() // Disable all dates after specific date
                    //   customPredictor: function (date) {
                    //     // disables the date if it is a multiple of 5
                    //     var newDate = new Date().getTime();
                    //     var EightteenYears = new Date().setTime(
                    //       new Date().getTime() - 6574.365 * 24 * 60 * 60
                    //     );
                    //     var test = newDate - EightteenYears;
                    //     console.log(EightteenYears);
                    //     if (test == 568025136) {
                    //       return true;
                    //     }
                    //   },
                }
            }
        };
    },

    mounted() {
        loading: false;

        setTimeout(() => {
            axios
                .get("/api/countries")
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

            this.fields.fingerData = document.querySelector(
                "input[name=fingerData]"
            ).value;
            this.fields.fingerCode = document.querySelector(
                "input[name=fingerCode]"
            ).value;

            let formData = new FormData();

            for (var key in this.fields) {
                formData.append(key, this.fields[key]);
            }

            axios
                .post("/api/one-sim/minor/register", formData, {
                    headers: {
                        "Content-Type": "multipart/form-data"
                    }
                })
                .then(response => {
                    loader.hide();
                    //this.fields = {}; //Clear input fields.

                    //   Swal.fire({
                    //     icon: "success",
                    //     title: "Success",
                    //     text: "Registration completed successfully !",
                    //   }).then(
                    //     setTimeout(() => {
                    //       window.location = "/home";
                    //     }, 3000)
                    //   );
                })
                .catch(error => {
                    this.loaded = true;
                    loader.hide();

                    if (error.response.status === 422) {
                        this.errors = error.response.data.errors || {};
                    } else if (error.response.status === 400) {
                        this.message = error.response.data.message;
                    } else {
                        this.message = "An error has occured !";
                    }
                });
        },

        handleIDFileUpload() {
            this.fields.IDFile = this.$refs.IDFile.files[0];
        },
        handlePotraitFileUpload() {
            this.fields.potraitFile = this.$refs.potraitFile.files[0];
        },

        onMinorGenderChange(e) {
            //console.log(response);
            this.fields.minorGender = e.target.value;
        },
        onMinorCountryChange(e) {
            this.fields.minorNationality = e.target.value;
        }
    }
};
</script>
