<template>
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-12">
            <div
                v-show="message"
                class="alert alert-warning alert-block text-center"
            >
                <span class="lead">{{ message }}</span>
            </div>
            <div class="card b">
                <div class="card-body">
                    <form @submit.prevent="submit" class="mb-3">
                        <div class="align-center">
                            <div class="form-row">
                                <div class="form-group col-4">
                                    <label class="text-bold">MSISDN</label>
                                    <input
                                        id="msisdn"
                                        name="msisdn"
                                        class="form-control"
                                        type="text"
                                        v-model="fields.msisdn"
                                        placeholder="Enter phone number e.g 0754..."
                                    />
                                    <div
                                        v-if="errors && errors.msisdn"
                                        class="text-danger"
                                    >
                                        {{ errors.msisdn[0] }}
                                    </div>
                                </div>

                                <div class="form-group col-4">
                                    <label class="text-bold">NIDA Number</label>
                                    <input
                                        id="NIN"
                                        name="NIN"
                                        class="form-control"
                                        type="text"
                                        v-model="fields.NIN"
                                        placeholder="Enter NIDA ID number"
                                    />
                                    <div
                                        v-if="errors && errors.NIN"
                                        class="text-danger"
                                    >
                                        {{ errors.NIN[0] }}
                                    </div>
                                </div>

                                <div class="form-group col-4">
                                    <button
                                        id="filterRegJourneyDates"
                                        type="submit"
                                        class="btn btn-lg btn-block btn-outline-danger myLead text-bold mt-4"
                                    >
                                        Check & Proceed
                                    </button>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <!-- END dashboard main content-->
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
            loading: false,
            message: null,
            checked: false,
            hasValue: false,
            items: null,
            showRegisterNew: false,
            categories: [
                { ID: "N", Description: "National ID(NIDA)" },
                {
                    ID: "P",
                    Description: "Passport"
                }
            ]
        };
    },
    mounted() {
        this.hasValue = false;
        this.showRegisterNew = false;
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
                this.hasValue = false;
                this.showRegisterNew = false;

                axios
                    .post("/api/nida/check-msisdn", this.fields)
                    .then(res => {
                        loader.hide();

                        this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        // this.success = true;
                        this.loading = false;

                        if (res.data.status === 2) {
                            window.location = "/one-sim/new-reg/primary";
                        } else if (res.data.status === 1) {
                            window.location = "/one-sim/new-reg/secondary";
                        }
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
        onIDTypeChange(e) {
            //console.log(response);
            this.fields.idType = e.target.value;
        }
    }
};
</script>
