// Import Tinytest from the tinytest Meteor package.
import { Tinytest } from "meteor/tinytest";

// Import and rename a variable exported by accounts-password-phone.js.
import { name as packageName } from "meteor/pablor21:accounts-password-phone";

// Write your tests here!
// Here is an example.
Tinytest.add('accounts-password-phone - example', function (test) {
  test.equal(packageName, "accounts-password-phone");
});
