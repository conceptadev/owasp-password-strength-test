let should = require('should');
let OwaspPST  = require('./owasp-password-strength-test');

describe('passwords', function() {

  describe('required tests', function() {

    it('minLength should be enforced', function() {
      let owasp = new OwaspPST();
      let result = owasp.test('L0^eSex');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.requiredTestErrors.should.have.length(1);
      result.failedTests.should.containEql(0);
    });

    it('maxLength should be enforced', function() {
      let password = '';
      for (let i = 0; i < 50; i++) {
        password += 'abc';
      }

      let owasp = new OwaspPST();
      let result = owasp.test(password);
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.requiredTestErrors.should.have.length(1);
      result.failedTests.should.containEql(1);
    });

    it('repeating characters (3 times or more) should be forbidden', function() {
      let owasp = new OwaspPST();
      let result = owasp.test('L0veSexxxSecre+God');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.requiredTestErrors.should.have.length(1);
      result.failedTests.should.containEql(2);
    });
  });

  describe('optional tests', function() {

    it('valid passwords should be recognized as such', function() {
      let owasp = new OwaspPST();
      let result = owasp.test('L0veSexSecre+God');
      result.strong.should.be.true;
      result.errors.should.be.empty;
      result.requiredTestErrors.should.be.empty;
      result.optionalTestErrors.should.be.empty;
      result.failedTests.should.be.empty;
      result.passedTests.should.eql([0, 1, 2, 3, 4, 5, 6]);
    });

    it('at least one lowercase character should be required', function() {
      let owasp = new OwaspPST();
      let result = owasp.test('L0VESEXSECRE+GOD');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(3);
    });

    it('at least one uppercase character should be required', function() {
      let owasp = new OwaspPST();
      let result = owasp.test('l0vesexsecre+god');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(4);
    });

    it('at least one number should be required', function() {
      let owasp = new OwaspPST();
      let result = owasp.test('LoveSexSecre+God');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(5);
    });

    it('at least one special character should be required', function() {
      let owasp = new OwaspPST();
      let result = owasp.test('L0veSexSecretGod');
      result.strong.should.be.false;
      result.errors.should.have.length(1);
      result.optionalTestErrors.should.have.length(1);
      result.failedTests.should.containEql(6);
    });

    it('the appropriate characters should be recognized as special', function() {

      let owasp = new OwaspPST();

      // see: https://www.owasp.org/index.php/Password_special_characters
      let specials = ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'.split('');

      // test each special character
      specials.forEach(function(special) {
        let password = ['L0veSex', special, 'SecretGod'].join('');
        let result   = owasp.test(password);
        result.strong.should.be.true;
        result.errors.should.be.empty;
        result.requiredTestErrors.should.be.empty;
        result.optionalTestErrors.should.be.empty;
        result.failedTests.should.be.empty;
        result.passedTests.should.eql([0, 1, 2, 3, 4, 5, 6]);
      });
    });

  });
});

describe('passphrases', function() {

  it('should not be subject to optional tests by default', function() {
    let owasp = new OwaspPST();
    let result = owasp.test('Hack the planet! Hack the planet!');
    result.strong.should.be.true;
    result.errors.should.be.empty;
  });

  it('should be subject to optional tests per configuration', function() {
    let owasp = new OwaspPST();
    owasp.configure({ allowPassphrases: false });
    owasp.test('Hack the planet! Hack the planet!').strong.should.be.false;
  });

});

describe('configs', function() {

  it('should be settable', function() {
    let owasp = new OwaspPST();
    owasp.configure({
      allowPassphrases       : false,
      maxLength              : 5,
      minLength              : 5,
      minPhraseLength        : 5,
      minOptionalTestsToPass : 5,
    });
    owasp.config.allowPassphrases.should.be.false;
    owasp.config.maxLength.should.be.exactly(5);
    owasp.config.minLength.should.be.exactly(5);
    owasp.config.minPhraseLength.should.be.exactly(5);
    owasp.config.minOptionalTestsToPass.should.be.exactly(5);
  });

  it('should reject invalid parameter keys', function() {
    let owasp = new OwaspPST();
    owasp.configure({ foo: 'bar' });
    owasp.config.should.not.have.property('foo');
  });

});
