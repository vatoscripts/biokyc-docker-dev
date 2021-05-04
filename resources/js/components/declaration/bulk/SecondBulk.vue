<template>
    <div class="col-12">
        <div class="clearfix"></div>
        <div
            v-show="message"
            class="alert alert-danger alert-block mt-1 text-center"
        >
            <span class="lead">{{ message }}</span>
        </div>
        <form id="bulkRegSaveForm" @submit.prevent="submit" class="mb-3 p-3">
            <div class="form-group">
                <label class="font-weight-bold" for="blockReason"
                    >Reason for additional msisdn</label
                >
                <select
                    class="custom-select text-center"
                    id="tcraReason"
                    name="tcraReason"
                    @change="onReasonChange($event)"
                >
                    <option class value
                        >------------ Choose reason ------------</option
                    >
                    <option value="1003">For mobile financial services</option>
                    <option value="1004"
                        >Mobile number porting - with reasons</option
                    >
                    <option value="1005"
                        >Increase branches/shops or business</option
                    >
                    <option value="1006">Increase staff/employee</option>
                    <option value="1007"
                        >Test numbers for compliance purposes</option
                    >
                    <option value="1008"
                        >Test numbers for roaming partners</option
                    >
                </select>
                <div v-if="errors && errors.bulkTcraReason" class="text-danger">
                    {{ errors.bulkTcraReason[0] }}
                </div>
            </div>

            <div class="form-group">
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

            <div class="form-group">
                <label class="text-bold">MSISDN Attachment</label>
                <div class="custom-file">
                    <input
                        type="file"
                        ref="msisdnFile"
                        class="form-control-file"
                        name="msisdnFile"
                        v-on:change="handleMsisdnFileUpload()"
                    />
                    <div v-if="errors && errors.msisdnFile" class="text-danger">
                        {{ errors.msisdnFile[0] }}
                    </div>
                </div>
            </div>

            <button
                id="bulkRegSave"
                type="submit"
                class="btn lead btn-lg btn-danger"
            >
                Register
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
            categories: [
                { ID: "COMP", Description: "Company SIM Card Registration" },
                {
                    ID: "INST",
                    Description: "Institution SIM Card Registration"
                },
                { ID: "CEMP", Description: "Machine SIM Card Registration" }
            ]
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
                .post("/api/one-sim/bulk/declaration", formData, {
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

        handleMsisdnFileUpload() {
            this.fields.msisdnFile = this.$refs.msisdnFile.files[0];
        },

        onReasonChange(e) {
            this.fields.bulkTcraReason = e.target.value;
        }
    }
};
</script>
