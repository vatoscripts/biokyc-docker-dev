<template>
    <div class="row">
        <!-- START dashboard main content-->
        <div class="col-xl-12">
            <div
                v-show="message"
                class="alert alert-danger alert-block mt-1 text-center"
            >
                <span class="lead">{{ message }}</span>
            </div>
            <div class="card b">
                <div class="card-body">
                    <form
                        @submit.prevent="submit"
                        class="mb-3"
                        id="registerBulkForm"
                    >
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
                            class="text-danger"
                        >
                            {{ errors.companyName[0] }}
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="col-6" v-if="hasValue">
            <div class="card">
                <div class="card-body">
                    <form
                        @submit.prevent="onSelectCompany"
                        class="mb-3"
                        id="registerBulkForm"
                    >
                        <div class="form-group">
                            <p v-for="item in items" item :key="item.index">
                                <input
                                    id="company"
                                    name="company"
                                    type="radio"
                                    :value="item.CompanyName"
                                    v-model="fields.CompanyName"
                                />
                                <label class="text-bold">
                                    {{ item.CompanyName }}
                                </label>
                            </p>
                        </div>

                        <div
                            v-if="errors && errors.CompanyName"
                            class="text-danger mb-2"
                        >
                            {{ errors.CompanyName[0] }}
                        </div>

                        <button
                            id="registerBulkBtn"
                            type="submit"
                            class="btn btn-primary btn-lg"
                        >
                            Choose & Continue
                        </button>
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
                        console.log(res.data);
                        loader.hide();

                        if (res.data.length > 0) {
                            this.hasValue = true;
                            this.items = res.data;
                        } else {
                            this.message =
                                "No companies found. Please register as bulk !";
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
        onSelectCompany() {
            this.errors = {};

            axios
                .post("/api/one-sim/bulk/company-search", this.fields)
                .then(res => {
                    window.location = "/one-sim/bulk-declaration/second";
                })
                .catch(error => {
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
    }
};
</script>
