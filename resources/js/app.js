/**
 * First we will load all of this project's JavaScript dependencies which
 * includes Vue and other libraries. It is a great starting point when
 * building robust, powerful web applications using Vue and Laravel.
 */

window.Vue = require("vue");

import Datepicker from "vuejs-datepicker";

Vue.use(Datepicker);

import Swal from "sweetalert2";

window.Swal = Swal;

const Toast = Swal.mixin({
    toast: true,
    position: "top-end",
    showConfirmButton: false,
    timer: 5000
});

window.Toast = Toast;

// Import component
import Loading from "vue-loading-overlay";
// Import stylesheet
import "vue-loading-overlay/dist/vue-loading.css";

Vue.use(Loading);

require("./bootstrap");

/**
 * The following block of code may be used to automatically register your
 * Vue components. It will recursively scan this directory for the Vue
 * components and automatically register them with their "basename".
 *
 * Eg. ./components/ExampleComponent.vue -> <example-component></example-component>
 */

// const files = require.context('./', true, /\.vue$/i)
// files.keys().map(key => Vue.component(key.split('/').pop().split('.')[0], files(key).default))

// Vue.component(
//     "example-component",
//     require("./components/ExampleComponent.vue").default
// );

/**
 * BULK COMPONENTS
 */
Vue.component(
    "start-bulk",
    require("./components/registration/bulk/StartBulk.vue").default
);
Vue.component(
    "primary-spoc",
    require("./components/registration/bulk/primary/Spoc.vue").default
);
Vue.component(
    "primary-company",
    require("./components/registration/bulk/primary/Company.vue").default
);

Vue.component(
    "secondary-spoc",
    require("./components/registration/bulk/secondary/Spoc.vue").default
);
Vue.component(
    "secondary-company",
    require("./components/registration/bulk/secondary/Company.vue").default
);

/**
 * MINOR COMPONENTS
 */
Vue.component(
    "start-minor",
    require("./components/registration/minor/StartMinor.vue").default
);

Vue.component(
    "primary-minor",
    require("./components/registration/minor/PrimaryMinor.vue").default
);

/**
 * REPORTS COMPONENTS
 */
Vue.component(
    "reg-journey",
    require("./components/report/RegistrationJourney.vue").default
);

/** DIPLOMAT COMPONENTS */
Vue.component(
    "start-diplomat",
    require("./components/registration/diplomat/individual/Start.vue").default
);

Vue.component(
    "primary-diplomat",
    require("./components/registration/diplomat/individual/Primary.vue").default
);

Vue.component(
    "secondary-diplomat",
    require("./components/registration/diplomat/individual/Secondary.vue")
        .default
);

/** NIDA REGISTRATIONS COMPONENTS */
Vue.component(
    "check-nida",
    require("./components/registration/nida/Check.vue").default
);

Vue.component(
    "primary-nida",
    require("./components/registration/nida/Primary.vue").default
);

Vue.component(
    "secondary-nida",
    require("./components/registration/nida/Secondary.vue").default
);

/** VISITOR REGISTRATIONS COMPONENTS */
Vue.component(
    "check-passport",
    require("./components/registration/visitor/Check.vue").default
);

Vue.component(
    "visitor-primary",
    require("./components/registration/visitor/Primary.vue").default
);

Vue.component(
    "visitor-secondary",
    require("./components/registration/visitor/Secondary.vue").default
);

/** REGISTRATIONS DETAILS PER ID */
Vue.component(
    "id-registration-details",
    require("./components/support/IdRegistrationDetails.vue").default
);

/** BULK DECLARATION */

Vue.component(
    "start-bulk-declaration",
    require("./components/declaration/bulk/StartBulk.vue").default
);

Vue.component(
    "second-bulk-declaration",
    require("./components/declaration/bulk/SecondBulk.vue").default
);

/** INDIVIDUAL DECLARATION */
Vue.component(
    "start-primary-msisdn",
    require("./components/declaration/individual/StartPrimary.vue").default
);

Vue.component(
    "set-primary-msisdn",
    require("./components/declaration/individual/SetPrimary.vue").default
);

Vue.component(
    "start-secondary-msisdn",
    require("./components/declaration/individual/StartSecondary.vue").default
);

Vue.component(
    "set-secondary-msisdn",
    require("./components/declaration/individual/SetSecondary.vue").default
);

/** VISITOR ALTERNATIVE REGISTRATIONS */
Vue.component(
    "alt-visitor-all",
    require("./components/support/AllAltVisitor.vue").default
);

Vue.component(
    "single-alt-visitor-all",
    require("./components/support/SingleAltVisitor.vue").default
);

/** DE-REG  */
Vue.component(
    "dereg-nida",
    require("./components/deregistration/DeregNida.vue").default
);
Vue.component(
    "dereg-msisdn",
    require("./components/deregistration/DeregMsisdn.vue").default
);
Vue.component(
    "dereg-code",
    require("./components/deregistration/DeregCode.vue").default
);

/**
 * Next, we will create a fresh Vue application instance and attach it to
 * the page. Then, you may begin adding components to this application
 * or customize the JavaScript scaffolding to fit your unique needs.
 */

const app = new Vue({
    el: "#app",
    components: {
        Datepicker
    }
});
