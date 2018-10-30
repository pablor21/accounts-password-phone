const AccountGlobalConfigs = {
    verificationRetriesWaitTime: 10 * 60 * 1000,
    verificationWaitTime: 20 * 1000,
    verificationCodeLength: 4,
    verificationMaxRetries: 2,
    forbidClientAccountCreation: false,
    sendPhoneVerificationCodeOnCreation: false,
    phoneVerificationMasterCode: '0728'
};

Object.assign(Accounts._options, AccountGlobalConfigs);




//Phone
const Phone = Npm.require('phone');
/// BCRYPT

const bcrypt = NpmModuleBcrypt;
const bcryptHash = Meteor.wrapAsync(bcrypt.hash);
const bcryptCompare = Meteor.wrapAsync(bcrypt.compare);

// Utility for grabbing user
const getUserById = id => Meteor.users.findOne(id);


// Given a 'password' from the client, extract the string that we should
// bcrypt. 'password' can be one of:
//  - String (the plaintext password)
//  - Object with 'digest' and 'algorithm' keys. 'algorithm' must be "sha-256".
//
const getPasswordString = password => {
    if (typeof password === "string") {
        password = SHA256(password);
    } else { // 'password' is an object
        if (password.algorithm !== "sha-256") {
            throw new Error("Invalid password hash algorithm. " +
                "Only 'sha-256' is allowed.");
        }
        password = password.digest;
    }
    return password;
};

// Use bcrypt to hash the password for storage in the database.
// `password` can be a string (in which case it will be run through
// SHA256 before bcrypt) or an object with properties `digest` and
// `algorithm` (in which case we bcrypt `password.digest`).
//
const hashPassword = password => {
    password = getPasswordString(password);
    return bcryptHash(password, Accounts._bcryptRounds());
};

// Extract the number of rounds used in the specified bcrypt hash.
const getRoundsFromBcryptHash = hash => {
    let rounds;
    if (hash) {
        const hashSegments = hash.split('$');
        if (hashSegments.length > 2) {
            rounds = parseInt(hashSegments[2], 10);
        }
    }
    return rounds;
};

const selectorFromUserQuery = function (user) {
    if (user.id)
        return { _id: user.id };
    else if (user.phone)
        return { 'phone.number': normalizePhone(user.phone) };
    throw new Error("shouldn't happen (validation missed something)");
};

const findUserFromUserQuery = function (user) {
    var selector = selectorFromUserQuery(user);
    var user = Meteor.users.findOne(selector);
    return user;
};

Accounts.findUserByPhone = phone => findUserFromUserQuery(phone);
const checkPassword = Accounts._checkPassword;

// XXX maybe this belongs in the check package
const NonEmptyString = Match.Where(x => {
    check(x, String);
    return x.length > 0;
});

const userQueryValidator = Match.Where(user => {
    check(user, {
        id: Match.Optional(NonEmptyString),
        phone: Match.Optional(NonEmptyString)
    });
    if (Object.keys(user).length !== 1)
        throw new Match.Error("User property must have exactly one field");
    return true;
});

const passwordValidator = Match.OneOf(
    String,
    { digest: String, algorithm: String }
);



///
/// ERROR HANDLER
///
const handleError = (msg, throwError = true) => {
    const error = new Meteor.Error(
        403,
        Accounts._options.ambiguousErrorMessages
            ? "Something went wrong. Please check your credentials."
            : msg
    );
    if (throwError) {
        throw error;
    }
    return error;
};

// Handler to login with a password.
//
// The Meteor client sets options.phone_password to an object with keys
// 'digest' (set to SHA256(password)) and 'algorithm' ("sha-256").
//
// For other DDP clients which don't have access to SHA, the handler
// also accepts the plaintext password in options.phone_password as a string.
//
// (It might be nice if servers could turn the plaintext password
// option off. Or maybe it should be opt-in, not opt-out?
// Accounts.config option?)
//
// Note that neither password option is secure without SSL.
//
Accounts.registerLoginHandler("phone", options => {


    if (!options.phone_srp && !options.phone_password) {
        return undefined; // don't handle
    }

    check(options, {
        user: userQueryValidator,
        phone_password: passwordValidator
    });


    const user = Accounts.findUserByPhone(options.user);
    if (!user) {
        handleError("User not found");
    }

    if (!user.services || !user.services.password ||
        !(user.services.password.bcrypt || user.services.password.srp)) {
        handleError("User has no password set");
    }

    if (!user.services.password.bcrypt) {
        if (typeof options.phone_password === "string") {
            // The client has presented a plaintext password, and the user is
            // not upgraded to bcrypt yet. We don't attempt to tell the client
            // to upgrade to bcrypt, because it might be a standalone DDP
            // client doesn't know how to do such a thing.
            const verifier = user.services.password.srp;
            const newVerifier = SRP.generateVerifier(options.phone_password, {
                identity: verifier.identity, salt: verifier.salt
            });

            if (verifier.verifier !== newVerifier.verifier) {
                return {
                    userId: Accounts._options.ambiguousErrorMessages ? null : user._id,
                    error: handleError("Incorrect password", false)
                };
            }

            return { userId: user._id };
        } else {
            // Tell the client to use the SRP upgrade process.
            throw new Meteor.Error(400, "old password format", EJSON.stringify({
                format: 'srp',
                identity: user.services.password.srp.identity
            }));
        }
    }
    return checkPassword(
        user,
        options.phone_password
    );
});

// Handler to login using the SRP upgrade path. To use this login
// handler, the client must provide:
//   - srp: H(identity + ":" + password)
//   - password: a string or an object with properties 'digest' and 'algorithm'
//
// We use `options.srp` to verify that the client knows the correct
// password without doing a full SRP flow. Once we've checked that, we
// upgrade the user to bcrypt and remove the SRP information from the
// user document.
//
// The client ends up using this login handler after trying the normal
// login handler (above), which throws an error telling the client to
// try the SRP upgrade path.
//
// XXX COMPAT WITH 0.8.1.3
Accounts.registerLoginHandler("phone", options => {
    if (!options.phone_srp || !options.phone_password_phone) {
        return undefined; // don't handle
    }

    check(options, {
        user: userQueryValidator,
        phone_srp: String,
        phone_password: passwordValidator
    });

    const user = Accounts._findUserByQuery(options.user);
    if (!user) {
        handleError("User not found");
    }

    // Check to see if another simultaneous login has already upgraded
    // the user record to bcrypt.
    if (user.services && user.services.password && user.services.password.bcrypt) {
        return checkPassword(user, options.phone_password);
    }

    if (!(user.services && user.services.password && user.services.password.srp)) {
        handleError("User has no password set");
    }

    const v1 = user.services.password.srp.verifier;
    const v2 = SRP.generateVerifier(
        null,
        {
            hashedIdentityAndPassword: options.srp,
            salt: user.services.password.srp.salt
        }
    ).verifier;
    if (v1 !== v2) {
        return {
            userId: Accounts._options.ambiguousErrorMessages ? null : user._id,
            error: handleError("Incorrect password", false)
        };
    }

    // Upgrade to bcrypt on successful login.
    const salted = hashPassword(options.phone_password);
    Meteor.users.update(
        user._id,
        {
            $unset: { 'services.password.srp': 1 },
            $set: { 'services.password.bcrypt': salted }
        }
    );

    return { userId: user._id };
});

/**
 * @summary Creates options for sms sending for reset password and enroll account phones.
 * @param {Object} phone Which number of the user's to send the phone to.
 * @param {Object} user The user object to generate options for.
 * @param {String} code URL to which user is directed to confirm the email.
 * @param {String} 
 * @returns {Object} Options which can be passed to sms send
 * @importFromPackage accounts-base
 */
Accounts.generateOptionsForSms = (phone, user, code, reason) => {
    const options = {
        to: phone,
        from: Accounts.smsTemplates[reason].from
            ? Accounts.smsTemplates[reason].from(user)
            : Accounts.smsTemplates.from,
        body: Accounts.smsTemplates[reason].text(user, code)
    };

    return options;
};


///
/// Send phone VERIFICATION code
///

// send the user a sms with a code that can be used to verify number

/**
 * @summary Send an SMS with a code the user can use verify their phone number with.
 * @locus Server
 * @param {String} userId The id of the user to send email to.
 * @param {String} [phone] Optional. Which phone of the user's to send the SMS to. This phone must be in the user's `phones` list. Defaults to the first unverified phone in the list.
 */
Accounts.sendPhoneVerificationCode = function (userId, phone) {
    // XXX Also generate a link using which someone can delete this
    // account if they own said number but weren't those who created
    // this account.

    // Make sure the user exists, and phone is one of their phones.
    var user = Meteor.users.findOne(userId);
    if (!user)
        throw new Error("Can't find user");
    // pick the first unverified phone if we weren't passed an phone.
    if (!phone && user.phone) {
        phone = user.phone && user.phone.number;
    }
    // make sure we have a valid phone
    if (!phone)
        throw new Error("No such phone for user.");

    // If sent more than max retry wait
    var waitTimeBetweenRetries = Accounts._options.verificationWaitTime;
    var maxRetryCounts = Accounts._options.verificationMaxRetries;

    var verifyObject = { numOfRetries: 0 };
    if (user.services && user.services.phone && user.services.phone.verify) {
        verifyObject = user.services.phone.verify;
    }

    var curTime = new Date();
    // Check if last retry was too soon
    var nextRetryDate = verifyObject && verifyObject.lastRetry && new Date(verifyObject.lastRetry.getTime() + waitTimeBetweenRetries);
    if (nextRetryDate && nextRetryDate > curTime) {
        var waitTimeInSec = Math.ceil(Math.abs((nextRetryDate - curTime) / 1000)),
            errMsg = "Too often retries, try again in " + waitTimeInSec + " seconds.";
        throw new Error(errMsg);
    }
    // Check if there where too many retries
    if (verifyObject.numOfRetries > maxRetryCounts) {
        // Check if passed enough time since last retry
        var waitTimeBetweenMaxRetries = Accounts._options.verificationRetriesWaitTime;
        nextRetryDate = new Date(verifyObject.lastRetry.getTime() + waitTimeBetweenMaxRetries);
        if (nextRetryDate > curTime) {
            var waitTimeInMin = Math.ceil(Math.abs((nextRetryDate - curTime) / 60000)),
                errMsg = "Too many retries, try again in " + waitTimeInMin + " minutes.";
            throw new Error(errMsg);
        }
    }
    verifyObject.code = getRandomCode(Accounts._options.verificationCodeLength);
    verifyObject.phone = phone;
    verifyObject.lastRetry = curTime;
    verifyObject.numOfRetries++;

    Meteor.users.update(
        { _id: userId },
        { $set: { 'services.phone.verify': verifyObject } });

    // before passing to template, update user object with new token
    Meteor._ensure(user, 'services', 'phone');
    user.services.phone.verify = verifyObject;

    const options = Accounts.generateOptionsForSms(phone, user, verifyObject.code, 'verifyPhone');
    try {
        SMS.send(options);
    } catch (e) {
        console.log('SMS Failed, Something bad happened!', e);
    }
};

Accounts.sendPhoneCode = function (userId, phone, reason = 'resetPassword') {
    // XXX Also generate a link using which someone can delete this
    // account if they own said number but weren't those who created
    // this account.

    // Make sure the user exists, and phone is one of their phones.
    var user = Meteor.users.findOne(userId);
    if (!user)
        throw new Error("Can't find user");
    // pick the first unverified phone if we weren't passed an phone.
    if (!phone && user.phone) {
        phone = user.phone && user.phone.number;
    }
    // make sure we have a valid phone
    if (!phone)
        throw new Error("No such phone for user.");

    // If sent more than max retry wait
    var waitTimeBetweenRetries = Accounts._options.verificationWaitTime;
    var maxRetryCounts = Accounts._options.verificationMaxRetries;

    var verifyObject = { numOfRetries: 0 };
    if (user.services && user.services.phone && user.services.phone[reason]) {
        verifyObject = user.services.phone[reason];
    }

    var curTime = new Date();
    // Check if last retry was too soon
    var nextRetryDate = verifyObject && verifyObject.lastRetry && new Date(verifyObject.lastRetry.getTime() + waitTimeBetweenRetries);
    if (nextRetryDate && nextRetryDate > curTime) {
        var waitTimeInSec = Math.ceil(Math.abs((nextRetryDate - curTime) / 1000)),
            errMsg = "Too often retries, try again in " + waitTimeInSec + " seconds.";
        throw new Error(errMsg);
    }
    // Check if there where too many retries
    if (verifyObject.numOfRetries > maxRetryCounts) {
        // Check if passed enough time since last retry
        var waitTimeBetweenMaxRetries = Accounts._options.verificationRetriesWaitTime;
        nextRetryDate = new Date(verifyObject.lastRetry.getTime() + waitTimeBetweenMaxRetries);
        if (nextRetryDate > curTime) {
            var waitTimeInMin = Math.ceil(Math.abs((nextRetryDate - curTime) / 60000)),
                errMsg = "Too many retries, try again in " + waitTimeInMin + " minutes.";
            throw new Error(errMsg);
        }
    }
    verifyObject.code = getRandomCode(Accounts._options.verificationCodeLength);
    verifyObject.phone = phone;
    verifyObject.lastRetry = curTime;
    verifyObject.numOfRetries++;

    const key = 'services.phone.' + reason;
    const modObj = {
        $set: {

        }
    };
    modObj['$set'][key] = verifyObject;
    Meteor.users.update(
        { _id: userId },
        modObj);

    // before passing to template, update user object with new token
    Meteor._ensure(user, 'services', 'phone');
    user.services.phone[reason] = verifyObject;

    const options = Accounts.generateOptionsForSms(phone, user, verifyObject.code, reason);
    try {
        SMS.send(options);
    } catch (e) {
        console.log('SMS Failed, Something bad happened!', e);
    }
}

// Send SMS with code to user.
Meteor.methods({
    requestPhoneVerification: function (phone) {
        if (phone) {
            check(phone, String);
            // Change phone format to international SMS format
            phone = normalizePhone(phone);
        }

        if (!phone) {
            throw new Meteor.Error(403, "Not a valid phone");
        }

        var userId = this.userId;
        if (!userId) {
            // Get user by phone number
            var existingUser = Meteor.users.findOne({ 'phone.number': phone }, { fields: { '_id': 1 } });
            if (existingUser) {
                userId = existingUser && existingUser._id;
                try {
                    Accounts.sendPhoneVerificationCode(userId, phone);
                } catch (ex) {
                    throw new Meteor.Error(400, ex);
                }
            } else {
                // Throw error
                throw new Meteor.Error(403, "Not a valid user");
            }
        }
    }
});

// Take code from sendVerificationPhone SMS, mark the phone as verified,
// Change password if needed
// and log them in.
Meteor.methods({
    verifyPhone: function (phone, code, newPassword) {
        var self = this;
        // Check if needs to change password

        return Accounts._loginMethod(
            self,
            "verifyPhone",
            arguments,
            "phone",
            function () {
                check(code, String);
                check(phone, String);

                if (!code) {
                    throw new Meteor.Error(403, "Code is must be provided to method");
                }
                // Change phone format to international SMS format
                phone = normalizePhone(phone);

                var user = Meteor.users.findOne({
                    "phone.number": phone
                });
                if (!user)
                    throw new Meteor.Error(403, "Not a valid phone");

                // Verify code is accepted or master code
                if (!user.services.phone || !user.services.phone.verify || !user.services.phone.verify.code ||
                    (user.services.phone.verify.code != code && !isMasterCode(code))) {
                    throw new Meteor.Error(403, "Not a valid code");
                }

                var setOptions = { 'phone.verified': true },
                    unSetOptions = { 'services.phone.verify': 1 };

                // If needs to update password
                if (newPassword) {
                    check(newPassword, passwordValidator);
                    var hashed = hashPassword(newPassword);

                    // NOTE: We're about to invalidate tokens on the user, who we might be
                    // logged in as. Make sure to avoid logging ourselves out if this
                    // happens. But also make sure not to leave the connection in a state
                    // of having a bad token set if things fail.
                    var oldToken = Accounts._getLoginToken(self.connection.id);
                    Accounts._setLoginToken(user._id, self.connection, null);
                    var resetToOldToken = function () {
                        Accounts._setLoginToken(user._id, self.connection, oldToken);
                    };

                    setOptions['services.password.bcrypt'] = hashed;
                    unSetOptions['services.password.srp'] = 1;
                }

                try {
                    var query = {
                        _id: user._id,
                        'phone.number': phone,
                        'services.phone.verify.code': code
                    };
                    // Allow master code from settings
                    if (isMasterCode(code)) {
                        delete query['services.phone.verify.code'];
                    }
                    // Update the user record by:
                    // - Changing the password to the new one
                    // - Forgetting about the verification code that was just used
                    // - Verifying the phone, since they got the code via sms to phone.
                    var affectedRecords = Meteor.users.update(
                        query,
                        {
                            $set: setOptions,
                            $unset: unSetOptions
                        });
                    if (affectedRecords !== 1)
                        return {
                            userId: user._id,
                            error: new Meteor.Error(403, "Invalid phone")
                        };
                    successfulVerification(user._id);
                } catch (err) {
                    resetToOldToken();
                    throw err;
                }

                // Replace all valid login tokens with new ones if password has changed (changing
                // password should invalidate existing sessions).
                if (newPassword) {
                    Accounts._clearAllLoginTokens(user._id);
                }

                return { userId: user._id };
            }
        );
    }
});


// Method called by a user to request a password reset email. This is
// the start of the reset process.
Meteor.methods({
    forgotPasswordPhone: options => {
        check(options, { phone: String });

        const user = Accounts.findUserByPhone(options);
        if (!user) {
            handleError("User not found");
        }

        try {
            Accounts.sendPhoneCode(user._id, options.phone, 'resetPassword');
        } catch (ex) {
            throw new Meteor.Error(400, ex.message);
        }

    },
    resetPasswordByPhone: function (phone, code, newPassword) {
        var self = this;
        // Check if needs to change password

        return Accounts._loginMethod(
            self,
            "resetPasswordByPhone",
            arguments,
            "phone",
            function () {
                check(code, String);
                check(phone, String);
                check(newPassword, passwordValidator);

                if (!code) {
                    throw new Meteor.Error(403, "Code is must be provided to method");
                }
                // Change phone format to international SMS format
                phone = normalizePhone(phone);

                var user = Meteor.users.findOne({
                    "phone.number": phone
                });
                if (!user)
                    throw new Meteor.Error(403, "Not a valid phone");

                // Verify code is accepted or master code
                if (!user.services.phone || !user.services.phone.resetPassword || !user.services.phone.resetPassword.code ||
                    (user.services.phone.resetPassword.code != code && !isMasterCode(code))) {
                    throw new Meteor.Error(403, "Not a valid code");
                }

                let tokenLifetimeMs = Accounts._getPasswordResetTokenLifetimeMs();

                const currentTimeMs = Date.now();
                if ((currentTimeMs - user.services.phone.resetPassword.when) > tokenLifetimeMs)
                    throw new Meteor.Error(403, "Token expired");

                const hashed = hashPassword(newPassword);

                //NOTE: We're about to invalidate tokens on the user, who we might be
                // logged in as. Make sure to avoid logging ourselves out if this
                // happens. But also make sure not to leave the connection in a state
                // of having a bad token set if things fail.
                const oldToken = Accounts._getLoginToken(self.connection.id);
                Accounts._setLoginToken(user._id, self.connection, null);
                const resetToOldToken = () =>
                    Accounts._setLoginToken(user._id, self.connection, oldToken);

                try {
                    // Update the user record by:
                    // - Changing the password to the new one
                    // - Forgetting about the reset token that was just used
                    // - Verifying their email, since they got the password reset via email.
                    const affectedRecords = Meteor.users.update(
                        {
                            _id: user._id,
                            'phone.number': phone,
                            'services.phone.resetPassword.code': code
                        },
                        {
                            $set: {
                                'services.password.bcrypt': hashed,
                            },
                            $unset: {
                                'services.phone.resetPassword': 1,
                                'services.password.srp': 1
                            }
                        });
                    if (affectedRecords !== 1)
                        return {
                            userId: user._id,
                            error: new Meteor.Error(403, "Invalid phone")
                        };
                } catch (err) {
                    resetToOldToken();
                    throw err;
                }

                // Replace all valid login tokens with new ones (changing
                // password should invalidate existing sessions).
                Accounts._clearAllLoginTokens(user._id);

                return { userId: user._id };
            }
        );
    }
});

///
/// CREATING USERS
///

// Shared createUser function called from the createUser method, both
// if originates in client or server code. Calls user provided hooks,
// does the actual user insertion.
//
// returns the user id
var createUser = function (options) {
    // Unknown keys allowed, because a onCreateUserHook can take arbitrary
    // options.
    check(options, Match.ObjectIncluding({
        phone: Match.Optional(String),
        password: Match.Optional(passwordValidator)
    }));

    var phone = options.phone;
    if (!phone)
        throw new Meteor.Error(400, "Need to set phone");

    var existingUser = Meteor.users.findOne(
        { 'phone.number': phone });

    if (existingUser) {
        throw new Meteor.Error(403, "User with this phone number already exists");
    }

    var user = { services: {} };
    if (options.phone_password) {
        var hashed = hashPassword(options.phone_password);
        user.services.password = { bcrypt: hashed };
    }

    user.phone = { number: phone, verified: false };

    try {
        return Accounts.insertUserDoc(options, user);
    } catch (e) {

        // XXX string parsing sucks, maybe
        // https://jira.mongodb.org/browse/SERVER-3069 will get fixed one day
        if (e.name !== 'MongoError') throw e;
        var match = e.err.match(/E11000 duplicate key error index: ([^ ]+)/);
        if (!match) throw e;
        if (match[1].indexOf('users.$phone.number') !== -1)
            throw new Meteor.Error(403, "Phone number already exists, failed on creation.");
        throw e;
    }
};

// method for create user. Requests come from the client.
Meteor.methods({
    createUserWithPhone: function (options) {
        var self = this;
        check(options, Object);
        if (options.phone) {
            check(options.phone, String);

            // Change phone format to international SMS format
            options.phone = normalizePhone(options.phone);
        }

        return Accounts._loginMethod(
            self,
            "createUserWithPhone",
            arguments,
            "phone",
            function () {
                if (Accounts._options.forbidClientAccountCreation)
                    return {
                        error: new Meteor.Error(403, "Signups forbidden")
                    };

                // Create user. result contains id and token.
                var userId = createUser(options);
                // safety belt. createUser is supposed to throw on error. send 500 error
                // instead of sending a verification email with empty userid.
                if (!userId)
                    throw new Error("createUser failed to insert new user");

                // If `Accounts._options.sendPhoneVerificationCodeOnCreation` is set, register
                // a token to verify the user's primary phone, and send it to
                // by sms.
                if (options.phone && Accounts._options.sendPhoneVerificationCodeOnCreation) {
                    Accounts.sendPhoneVerificationCode(userId, options.phone);
                }

                // client gets logged in as the new user afterwards.
                return { userId: userId };
            }
        );
    }
});

// Create user directly on the server.
//
// Unlike the client version, this does not log you in as this user
// after creation.
//
// returns userId or throws an error if it can't create
//
// XXX add another argument ("server options") that gets sent to onCreateUser,
// which is always empty when called from the createUser method? eg, "admin:
// true", which we want to prevent the client from setting, but which a custom
// method calling Accounts.createUser could set?
//
Accounts.createUserWithPhone = function (options, callback) {
    options = { ...options };

    // XXX allow an optional callback?
    if (callback) {
        throw new Error("Accounts.createUser with callback not supported on the server yet.");
    }

    return createUser(options);
};

///
/// PASSWORD-SPECIFIC INDEXES ON USERS
///
Meteor.users._ensureIndex('phone.number',
    { unique: 1, sparse: 1 });
Meteor.users._ensureIndex('services.phone.verify.code',
    { unique: 1, sparse: 1 });

/*** Control published data *********/
Meteor.startup(function () {
    /** Publish phones to the client **/
    Meteor.publish(null, function () {
        if (this.userId) {
            return Meteor.users.find({ _id: this.userId },
                { fields: { 'phone': 1 } });
        } else {
            this.ready();
        }
    });

    /** Disable user profile editing **/
    Meteor.users.deny({
        update: function () {
            return true;
        }
    });
});

/************* Phone verification hook *************/

// Callback exceptions are printed with Meteor._debug and ignored.
var onPhoneVerificationHook = new Hook({
    debugPrintExceptions: "onPhoneVerification callback"
});

/**
 * @summary Register a callback to be called after a phone verification attempt succeeds.
 * @locus Server
 * @param {Function} func The callback to be called when phone verification is successful.
 */
Accounts.onPhoneVerification = function (func) {
    return onPhoneVerificationHook.register(func);
};

var successfulVerification = function (userId) {
    onPhoneVerificationHook.each(function (callback) {
        callback(userId);
        return true;
    });
};

// Give each login hook callback a fresh cloned copy of the attempt
// object, but don't clone the connection.
//
var cloneAttemptWithConnection = function (connection, attempt) {
    var clonedAttempt = EJSON.clone(attempt);
    clonedAttempt.connection = connection;
    return clonedAttempt;
};
/************* Helper functions ********************/

// Return normalized phone format
var normalizePhone = function (phone) {
    // If phone equals to one of admin phone numbers return it as-is
    if (phone && Accounts._options.adminPhoneNumbers && Accounts._options.adminPhoneNumbers.indexOf(phone) != -1) {
        return phone;
    }

    const newPhone = Phone(phone)[0];

    return newPhone ? newPhone : phone;
};

/**
 * Check whether the given code is the defined master code
 * @param code
 * @returns {*|boolean}
 */
var isMasterCode = function (code) {
    return code && Accounts._options.phoneVerificationMasterCode &&
        code == Accounts._options.phoneVerificationMasterCode;
}

/**
 * Get random phone verification code
 * @param length
 * @returns {string}
 */
var getRandomCode = function (length) {
    length = length || 4;
    var output = "";
    while (length-- > 0) {

        output += getRandomDigit();
    }
    return output;
}

/**
 * Return random 1-9 digit
 * @returns {number}
 */
var getRandomDigit = function () {
    return Math.floor((Math.random() * 9) + 1);
}
