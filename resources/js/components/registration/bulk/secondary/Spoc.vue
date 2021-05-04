<template>
    <div class="col-8">
        <div class="clearfix"></div>
        <div
            v-show="message"
            class="alert alert-warning alert-block text-center"
        >
            <span class="lead">{{ message }}</span>
        </div>
        <form @submit.prevent="submit" class="mb-3">
            <div class="form-row">
                <div class="col-md-12 col-xs-12 mb-3">
                    <label class="text-bold">SPOC MSISDN</label>
                    <input
                        name="spocMsisdn"
                        value
                        type="text"
                        class="form-control"
                        id="spoc-msisdn"
                        placeholder="Enter SPOC MSISDN e.g 255754xxxxxx"
                        v-model="fields.spocMsisdn"
                    />
                    <div v-if="errors && errors.spocMsisdn" class="text-danger">
                        {{ errors.spocMsisdn[0] }}
                    </div>
                </div>
            </div>

            <div class="form-group">
                <label class="text-bold" for="spocEmail"
                    >SPOC Email address</label
                >
                <input
                    name="spocEmail"
                    type="email"
                    class="form-control"
                    id="spocEmail"
                    aria-describedby="emailHelp"
                    placeholder="Enter SPOC Email"
                    v-model="fields.spocEmail"
                />
                <div v-if="errors && errors.spocEmail" class="text-danger">
                    {{ errors.spocEmail[0] }}
                </div>
            </div>

            <div class="row">
                <div class="form-group col-12">
                    <label class="text-bold">Region</label>
                    <select
                        class="custom-select"
                        id="regionID"
                        name="region"
                        @change="onRegionChange"
                    >
                        <option value>SELECT REGION</option>
                        <option
                            v-for="region in regions"
                            v-bind:value="region.ID"
                            v-bind:key="region.ID"
                            >{{ region.Description }}</option
                        >
                    </select>
                </div>
            </div>

            <div class="row">
                <div class="form-group col-12">
                    <label class="text-bold">District</label>
                    <select
                        name="district"
                        class="custom-select"
                        @change="onDistrictChange"
                        id="district-dropdown"
                    >
                        <option value>SELECT DISTRICT</option>
                        <option
                            v-for="district in districts"
                            v-bind:value="district.ID"
                            v-bind:key="district.ID"
                            >{{ district.Description }}</option
                        >
                    </select>
                </div>
            </div>

            <div class="row">
                <div class="form-group col-12">
                    <label class="text-bold">Ward</label>
                    <select
                        class="custom-select"
                        name="ward"
                        @change="onWardChange"
                        id="ward-dropdown"
                    >
                        <option value>SELECT WARD</option>
                        <option
                            v-for="ward in wards"
                            v-bind:value="ward.ID"
                            v-bind:key="ward.ID"
                            >{{ ward.Description }}</option
                        >
                    </select>
                </div>
            </div>

            <div class="row">
                <div class="form-group col-12">
                    <label class="text-bold">Street</label>
                    <select
                        class="custom-select"
                        name="village"
                        @change="onVillageChange"
                        id="village-dropdown"
                    >
                        <option value>SELECT STREET</option>
                        <option
                            v-for="village in villages"
                            v-bind:value="village.ID"
                            v-bind:key="village.ID"
                            >{{ village.Description }}</option
                        >
                    </select>
                    <div v-if="errors && errors.village" class="text-danger">
                        {{ errors.village[0] }}
                    </div>
                </div>
            </div>

            <div class="form-group">
                <label class="text-bold">NIDA Number</label>
                <input
                    id="NIN"
                    name="NIN"
                    class="form-control"
                    type="text"
                    placeholder="Enter NIDA number"
                    v-model="fields.NIN"
                />
                <div v-if="errors && errors.NIN" class="text-danger">
                    {{ errors.NIN[0] }}
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

            <div style="margin:6em">
                <table>
                    <tr valign="top">
                        <td>
                            <div class="backgroundA">
                                <input
                                    id="Radio1"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    type="radio"
                                    style="position:absolute; top: 49px; left: -9px;"
                                />
                                <input
                                    id="Radio2"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: -4px; left: 35px; height: 20px;"
                                />
                                <input
                                    id="Radio3"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: -17px; left: 95px;"
                                />
                                <input
                                    id="Radio4"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: -1px; left: 164px;"
                                />
                                <input
                                    id="Radio5"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: 125px; left: 219px;"
                                />
                                <input
                                    id="Radio6"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: 125px; left: 259px; width: 20px;"
                                />
                                <input
                                    id="Radio7"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: -1px; left: 315px;"
                                />
                                <input
                                    id="Radio8"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: -17px; left: 381px;"
                                />
                                <input
                                    id="Radio9"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: 0px; left: 446px;"
                                />
                                <input
                                    id="Radio10"
                                    type="radio"
                                    name="rdoFinger"
                                    onchange="getFingerName(this)"
                                    style="position:absolute; top: 45px; left: 485px; height: 20px;"
                                />
                                <div
                                    id="lblCapture"
                                    style="position:absolute; top: 200px; left: 218px; "
                                >
                                    <b>Select Finger</b>
                                </div>
                                <input
                                    id="Button1"
                                    type="button"
                                    value="Capture Fingerprint"
                                    class="btn btn-danger"
                                    onclick="Capture()"
                                    style="position:relative; top: 229px; left: 190px;"
                                />
                            </div>
                        </td>
                        <td style="padding:10px">
                            <div class="row">
                                <div
                                    class="col-sm-12"
                                    style="margin-bottom:10px;"
                                >
                                    <img
                                        id="FingerImage"
                                        src=" "
                                        style="height:130px; min-width:140px; border:solid 1px #CCCCCC;"
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
                <em class="fa mr-2 fas fa-arrow-right"></em> Proceed
            </button>
        </form>
    </div>
</template>

<script>
export default {
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
            villages: null
        };
    },
    mounted() {
        loading: false;

        setTimeout(() => {
            axios
                .get("/api/regions")
                .then(response => {
                    //console.log(response.data);
                    this.regions = response.data;
                })
                .catch(error => {
                    console.log(error);
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

            axios
                .post("/api/one-sim/bulk/primary-spoc", this.fields)
                .then(response => {
                    loader.hide();
                    this.fields = {}; //Clear input fields.

                    window.location = "/one-sim/bulk/secondary/register";
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
        },
        onRegionChange(e) {
            axios
                .get("/api/districts/" + e.target.value)
                .then(response => {
                    //console.log(response.data);
                    this.districts = response.data;
                    //   this.territories = null;
                    //   this.region = "";
                    //   this.fields.aggregatorTerritory = "";
                })
                .catch(error => {
                    console.log(error);
                });
        },

        onDistrictChange(e) {
            axios
                .get("/api/wards/" + e.target.value)
                .then(response => {
                    //console.log(response);
                    //this.fields.aggregatorTerritory = "";
                    this.wards = response.data;
                })
                .catch(error => {
                    console.log(error);
                });
        },
        onWardChange(e) {
            axios
                .get("/api/villages/" + e.target.value)
                .then(response => {
                    //console.log(response);
                    //this.fields.aggregatorTerritory = "";
                    this.villages = response.data;
                })
                .catch(error => {
                    console.log(error);
                });
        },
        onVillageChange(e) {
            this.fields.village = e.target.value;
        }
    }
};
</script>
