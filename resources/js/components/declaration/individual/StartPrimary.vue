<template>
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-12">
            <div
                v-show="message"
                class="alert alert-warning alert-block mt-1 text-center"
            >
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
                                    <label class="text-bold"
                                        >Customer ID Type</label
                                    >
                                    <select
                                        class="custom-select"
                                        id="country-select"
                                        name="idType"
                                        @change="onIDTypeChange($event)"
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
                                        v-if="errors && errors.idType"
                                        class="text-danger"
                                    >
                                        {{ errors.idType[0] }}
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
                },
                {
                    ID: "DP",
                    Description: "Diplomatic Passport"
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
                    .post("/api/primary/check-msisdn", this.fields)
                    .then(res => {
                        loader.hide();

                        window.location = "/one-sim/primary/set";

                        // this.fields = {}; //Clear input fields.
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
        onIDTypeChange(e) {
            this.fields.idType = e.target.value;
        }
    }
};
</script>
