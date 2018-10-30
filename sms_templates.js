const greet = welcomeMsg => (user, code) => {
    const greeting = (user.profile && user.profile.name) ?
        (`Hello ${user.profile.name},`) : "Hello,";

    return `${greeting} your ${welcomeMsg} code for ${Accounts.smsTemplates.siteName} is: ${code}. Thanks.`;
};

/**
* @summary Options to customize emails sent from the Accounts system.
* @locus Server
* @importFromPackage accounts-base
*/
Accounts.smsTemplates = {
    from: '+19999999999',
    siteName: Meteor.absoluteUrl().replace(/^https?:\/\//, '').replace(/\/$/, ''),

    resetPassword: {
        text: greet("reset password"),
    },
    verifyPhone: {
        text: greet("account verification"),
    },
    enrollAccount: {
        text: greet("account verification"),
    },
};