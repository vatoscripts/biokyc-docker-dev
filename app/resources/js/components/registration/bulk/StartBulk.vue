<template>
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-12">
            <div
                v-show="message"
                class="alert alert-warning alert-block text-center mb-2"
            >
                <span class="lead">{{ message }}</span>
            </div>
            <div class="card b">
                <div class="card-body">
                    <form @submit.prevent="submit">
                        <div class="form-group">
                            <div class="input-group with-focus mb-2">
                                <input
                                    name="companyName"
                                    class="form-control"
                                    id="companyName"
                                    type="text"
                                    v-model="fields.companyName"
                                    placeholder="Enter company name e.g Vodacom"
                                />
                                <div class="input-group-append">
                                    <button
                                        id="checkMsisdnIcapBtn"
                                        class="btn btn-block btn-info"
                                        type="submit"
                                    >
                                        <span class="fa fa-search-plus"></span>
                                        Search company
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div
                            v-if="errors && errors.companyName"
                            class="text-danger myLead"
                        >
                            {{ errors.companyName[0] }}
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="col-6 mt-3" v-if="!hasValue">
            <button
                v-if="showRegisterNew"
                class="btn btn-lg btn-block btn-outline-danger text-bold col-5"
                @click="onRegisterPrimary"
            >
                Register as new company
            </button>
        </div>
        <div class="col-6 mt-3" v-if="hasValue">
            <div class="card">
                <div class="card-body">
                    <form @submit.prevent class="mb-3">
                        <div class="form-group">
                            <p v-for="item in items" item :key="item.index">
                                <input
                                    id="company"
                                    name="company"
                                    type="radio"
                                    :value="item.CompanyName"
                                    @change="onSelectedCompanyName($event)"
                                />
                                <label class="text-bold">
                                    {{ item.CompanyName }}
                                </label>
                            </p>
                        </div>

                        <div
                            v-if="errors && errors.selectedCompanyName"
                            class="text-danger myLead mb-2"
                        >
                            {{ errors.selectedCompanyName[0] }}
                        </div>

                        <div class="row justify-content-around">
                            <button
                                id="registerBulkBtn"
                                type="button"
                                class="btn btn-lg btn-block btn-outline-danger text-bold mt-4 col-5"
                                @click="onRegisterSecondary"
                            >
                                Choose & Continue
                            </button>

                            <button
                                v-if="showRegisterNew"
                                class="btn btn-lg btn-block btn-outline-danger text-bold mt-4 col-5"
                                @click="onRegisterPrimary"
                            >
                                Register as new company
                            </button>
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
            showRegisterNew: false
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
                    .post("/api/one-sim/bulk/new-reg-post", this.fields)
                    .then(res => {
                        //console.log(res.data);
                        loader.hide();

                        if (res.data.length > 0) {
                            this.hasValue = true;
                            this.items = res.data;
                            this.showRegisterNew = true;
                        } else {
                            this.message = "No companies found !";
                            this.showRegisterNew = true;
                        }

                        //this.fields = {}; //Clear input fields.
                        this.loaded = true;
                        this.success = true;
                        this.loading = false;
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
            }
        },
        onRegisterSecondary() {
            this.errors = {};

            axios
                .post("/api/one-sim/bulk/company-search", this.fields)
                .then(res => {
                    window.location = "/one-sim/bulk/secondary/spoc";
                })
                .catch(error => {
                    console.log(error);
                    if (error.response.status === 422) {
                        this.errors = error.response.data.errors || {};
                    } else if (error.response.status === 400) {
                        this.message = error.response.data.message || {};
                    } else {
                        Toast.fire({
                            icon: "error",
                            title: "An error has occured !"
                        });
                    }
                });
        },

        onRegisterPrimary() {
            this.errors = {};
            this.message = null;

            axios
                .post("/api/one-sim/bulk/new-reg-search", this.fields)
                .then(res => {
                    window.location = "/one-sim/bulk/primary/spoc";
                })
                .catch(error => {
                    console.log(error.response.data.message);
                    if (error.response.status === 422) {
                        this.errors = error.response.data.errors || {};
                    }
                    if (error.response.status === 400) {
                        this.message = error.response.data.message || {};
                    } else {
                        this.message = "An error has occured !";
                    }
                });
        },
        onSelectedCompanyName(e) {
            this.fields.selectedCompanyName = e.target.value;
            //console.log(e.target.value);
        }
    }
};
</script>
