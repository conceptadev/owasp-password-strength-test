/* globals define */
(function (root, factory) {
  
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof exports === 'object') {
    module.exports = factory();
  } else {
    root.owaspPasswordStrengthTest = factory();
  }

  }(this, function () {

    class OwaspPasswordStrengthTest {

      constructor(options = {}) {

        this.config = {
          allowPassphrases       : true,
          maxLength              : 128,
          minLength              : 10,
          minPhraseLength        : 20,
          minOptionalTestsToPass : 4,
        };

        this.configure(options);

        this.tests = {

          // An array of required tests. A password *must* pass these tests in order
          // to be considered strong.
          required: [

            // enforce a minimum length
            (password) => {
              if (password.length < this.config.minLength) {
                return 'The password must be at least ' + this.config.minLength + ' characters long.';
              }
            },

            // enforce a maximum length
            (password) => {
              if (password.length > this.config.maxLength) {
                return 'The password must be fewer than ' + this.config.maxLength + ' characters.';
              }
            },

            // forbid repeating characters
            (password) => {
              if (/(.)\1{2,}/.test(password)) {
                return 'The password may not contain sequences of three or more repeated characters.';
              }
            },

          ],

          // An array of optional tests. These tests are "optional" in two senses:
          //
          // 1. Passphrases (passwords whose length exceeds
          //    this.configs.minPhraseLength) are not obligated to pass these tests
          //    provided that this.configs.allowPassphrases is set to Boolean true
          //    (which it is by default).
          //
          // 2. A password need only to pass this.configs.minOptionalTestsToPass
          //    number of these optional tests in order to be considered strong.
          optional: [

            // require at least one lowercase letter
            (password) => {
              if (!/[a-z]/.test(password)) {
                return 'The password must contain at least one lowercase letter.';
              }
            },

            // require at least one uppercase letter
            (password) => {
              if (!/[A-Z]/.test(password)) {
                return 'The password must contain at least one uppercase letter.';
              }
            },

            // require at least one number
            (password) => {
              if (!/[0-9]/.test(password)) {
                return 'The password must contain at least one number.';
              }
            },

            // require at least one special character
            (password) => {
              if (!/[^A-Za-z0-9]/.test(password)) {
                return 'The password must contain at least one special character.';
              }
            },

          ],
        };

      }

      configure(options) {
        for (let prop in options) {
          if (options.hasOwnProperty(prop) && this.config.hasOwnProperty(prop)) {
            this.config[prop] = options[prop];
          }
        }
      }

      test(password) {

        // create an object to store the test results
        let result = {
          errors              : [],
          failedTests         : [],
          passedTests         : [],
          requiredTestErrors  : [],
          optionalTestErrors  : [],
          isPassphrase        : false,
          strong              : true,
          optionalTestsPassed : 0,
        };

        // Always submit the password/passphrase to the required tests
        let i = 0;

        this.tests.required.forEach(function(test) {
          let err = test(password);
          if (typeof err === 'string') {
            result.strong = false;
            result.errors.push(err);
            result.requiredTestErrors.push(err);
            result.failedTests.push(i);
          } else {
            result.passedTests.push(i);
          }
          i++;
        });

        // If configured to allow passphrases, and if the password is of a
        // sufficient length to consider it a passphrase, exempt it from the
        // optional tests.
        if (
          this.config.allowPassphrases === true &&
          password.length >= this.config.minPhraseLength
        ) {
          result.isPassphrase = true;
        }

        if (!result.isPassphrase) {
          let j = this.tests.required.length;
          this.tests.optional.forEach(function(test) {
            let err = test(password);
            if (typeof err === 'string') {
              result.errors.push(err);
              result.optionalTestErrors.push(err);
              result.failedTests.push(j);
            } else {
              result.optionalTestsPassed++;
              result.passedTests.push(j);
            }
            j++;
          });
        }

        // If the password is not a passphrase, assert that it has passed a
        // sufficient number of the optional tests, per the configuration
        if (
          !result.isPassphrase &&
          result.optionalTestsPassed < this.config.minOptionalTestsToPass
        ) {
          result.strong = false;
        }

        // return the result
        return result;
      };

    }

    return OwaspPasswordStrengthTest;
  }

));
