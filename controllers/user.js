const { promisify } = require('util');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const _ = require('lodash');
const User = require('../models/User');

const randomBytesAsync = promisify(crypto.randomBytes);

/**
 * GET /login
 * Login page.
 */
exports.index = (req, res) => {
  if (req.user) {
    res.render('home', {
      title: 'Home'
    });
  } else { 
    res.render('account/login', {
      title: 'Home'
    });
  }
};

exports.addBank = (req, res) => {
  if (req.user) {
    res.render('account/addBank', {
      title: 'Home'
    });
  } else { 
    res.render('account/login', {
      title: 'Home'
    });
  }
};

exports.transfer = (req, res) => {
  if (req.user) {
    res.render('account/balances', {
      title: 'Home'
    });
  } else { 
    res.render('home', {
      title: 'Home'
    });
  }
};

exports.getLogin = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/login', {
    title: 'Login'
  });
};

exports.getLoggedIn = (req, res) => {
  if (req.user) {
    return;
  }
  res.render('account/login', {
    title: 'Login'
  });
};

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/login');
  }

  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash('errors', info);
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Success! You are logged in.' });
      res.redirect('/loggedIn');
    });
  })(req, res, next);
};

/**
 * GET /logout
 * Log out.
 */
exports.logout = (req, res) => {
  req.logout();
  req.session.destroy((err) => {
    if (err) console.log('Error : Failed to destroy the session during logout.', err);
    req.user = null;
    res.redirect('/');
  });
};

/**
 * GET /signup
 * Signup page.
 */
exports.getSignup = (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/signup', {
    title: 'Create Account'
  });
};

/**
 * POST /signup
 * Create a new local account.
 */
exports.postSignup = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/signup');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) { return next(err); }
    if (existingUser) {
      req.flash('errors', { msg: 'Account with that email address already exists.' });
      return res.redirect('/signup');
    }
    user.save((err) => {
      if (err) { return next(err); }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.redirect('/');
      });
    });
  });
};

/**
 * GET /account
 * Profile page.
 */
exports.getAccount = (req, res) => {
  res.render('account/profile', {
    title: 'Account Management'
  });
};

/**
 * POST /account/profile
 * Update profile information.
 */
exports.postUpdateProfile = (req, res, next) => {
  req.assert('email', 'Please enter a valid email address.').isEmail();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/account');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    user.email = req.body.email || '';
    user.profile.name = req.body.name || '';
    user.profile.gender = req.body.gender || '';
    user.profile.location = req.body.location || '';
    user.profile.website = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
    user.save((err) => {
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', { msg: 'The email address you have entered is already associated with an account.' });
          return res.redirect('/account');
        }
        return next(err);
      }
      req.flash('success', { msg: 'Profile information has been updated.' });
      res.redirect('/account');
    });
  });
};

exports.postAddBank = (req, res, next) => {
  if (!req.body.account || !req.body.routing || req.body.account == '000000000001' || req.body.routing == '000000000001') {
    req.flash('errors', { msg: 'Please check your account and routing numbers and try again.' })
    return res.redirect('/addBank');
  } else {

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/addBank');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    console.log(req.body.account + ':::' + req.body.routing + ':|:' + req.body.balance);
    console.log(req.body.propertyType);
    switch(req.body.propertyType) {
      case "6":
        user.bankofamerica = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "7":
        user.bbt = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "8":
        user.chase = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "9":
        user.citi = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "10":
        user.fifththirdbank = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "11":
        user.keybank = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "12":
        user.pnc = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "13":
        user.regions = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "14":
        user.tdbank = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "15":
        user.usbank = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      case "16":
        user.quicken = req.body.account + ':::' + req.body.routing + ':|:' + (req.body.balance || '0') || '';
        break;
      default:
        // code block
    }
    
    user.save((err) => {
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', { msg: 'The email address you have entered is already associated with an account.' });
          return res.redirect('/addBank');
        }
        return next(err);
      }
      req.flash('success', { msg: 'Bank information has been updated.' });
      res.redirect('/addBank');
    });
  });
}
};


exports.postGetUserBank = (req, res, next) => {
  console.log(req.body, req.body.bankName);
  User.findById(req.user.id, (err, user) => {
    if (err) { res.send(JSON.stringify(req.body.bankName)); }
    switch(req.body.bankName) {
      case "6":
        res.send(JSON.stringify(user.bankofamerica));
        break;
      case "7":
        res.send(JSON.stringify(user.bbt));
        break;
      case "8":
        res.send(JSON.stringify(user.chase));
        break;
      case "9":
        res.send(JSON.stringify(user.citi));
        break;
      case "10":
        res.send(JSON.stringify(user.fifththirdbank));
        break;
      case "11":
        res.send(JSON.stringify(user.keybank));
        break;
      case "12":
        res.send(JSON.stringify(user.pnc));
        break;
      case "13":
        res.send(JSON.stringify(user.regions));
        break;
      case "14":
        res.send(JSON.stringify(user.tdbank));
        break;
      case "15":
        res.send(JSON.stringify(user.usbank));
        break;
      case "16":
        console.log(JSON.stringify(user));
        res.send(JSON.stringify(user.quicken));
        break;
      default:
        res.send(req.body.bankName);
    }
  });
};


/**
 * POST /account/password
 * Update current password.
 */
exports.postUpdatePassword = (req, res, next) => {
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/account');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    user.password = req.body.password;
    user.save((err) => {
      if (err) { return next(err); }
      req.flash('success', { msg: 'Password has been changed.' });
      res.redirect('/account');
    });
  });
};

exports.postTransfer = (req, res, next) => {
  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/addBank');
  }

  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    console.log(req.body.account + ':::' + req.body.routing + ':|:' + req.body.amount);
    console.log(req.body.propertyType);
    switch(req.body.transferFrom) {
      case "6":
        user.bankofamerica =  user.bankofamerica.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "7":
        user.bbt =  user.bbt.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "8":
        user.chase =  user.chase.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "9":
        user.citi =  user.citi.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "10":
        user.fifththirdbank =  user.fifththirdbank.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "11":
        user.keybank = user.keybank.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "12":
        user.pnc =  user.pnc.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "13":
        user.regions = user.regions.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "14":
        user.tdbank =  user.tdbank.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "15":
        user.usbank =  user.usbank.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      case "16":
        user.quicken =  user.quicken.split(":|:")[0] + ':|:' + (parseInt(req.body.fromBalance) - parseInt(req.body.amount)) || '0';
        break;
      default:
        // code block
    }

    switch(req.body.transferTo) {
      case "6":
        user.bankofamerica =  user.bankofamerica.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "7":
        user.bbt = user.bbt.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "8":
        user.chase =  user.chase.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "9":
        user.citi =  user.citi.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "10":
        user.fifththirdbank =  user.fifththirdbank.split(":|:")[0]+ ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "11":
        user.keybank =  user.keybank.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "12":
        user.pnc =  user.pnc.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "13":
        user.regions =  user.regions.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "14":
        user.tdbank =  user.tdbank.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "15":
        user.usbank =  user.usbank.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      case "16":
        user.quicken = user.quicken.split(":|:")[0] + ':|:' + (parseInt(req.body.toBalance) + parseInt(req.body.amount)) || '0';
        break;
      default:
        // code block
    }
    
    user.save((err) => {
      if (err) {
        if (err.code === 11000) {
          req.flash('errors', { msg: 'The email address you have entered is already associated with an account.' });
          return res.redirect('/transfer');
        }
        return next(err);
      }
      req.flash('success', { msg: 'Bank information has been updated.' });
      res.redirect('/transfer');
    });
  });
};

/**
 * POST /account/delete
 * Delete user account.
 */
exports.postDeleteAccount = (req, res, next) => {
  User.deleteOne({ _id: req.user.id }, (err) => {
    if (err) { return next(err); }
    req.logout();
    req.flash('info', { msg: 'Your account has been deleted.' });
    res.redirect('/');
  });
};

/**
 * GET /account/unlink/:provider
 * Unlink OAuth provider.
 */
exports.getOauthUnlink = (req, res, next) => {
  const { provider } = req.params;
  User.findById(req.user.id, (err, user) => {
    if (err) { return next(err); }
    user[provider.toLowerCase()] = undefined;
    const tokensWithoutProviderToUnlink = user.tokens.filter(token =>
      token.kind !== provider.toLowerCase());
    // Some auth providers do not provide an email address in the user profile.
    // As a result, we need to verify that unlinking the provider is safe by ensuring
    // that another login method exists.
    if (
      !(user.email && user.password)
      && tokensWithoutProviderToUnlink.length === 0
    ) {
      req.flash('errors', {
        msg: `The ${_.startCase(_.toLower(provider))} account cannot be unlinked without another form of login enabled.`
          + ' Please link another account or add an email address and password.'
      });
      return res.redirect('/account');
    }
    user.tokens = tokensWithoutProviderToUnlink;
    user.save((err) => {
      if (err) { return next(err); }
      req.flash('info', { msg: `${_.startCase(_.toLower(provider))} account has been unlinked.` });
      res.redirect('/account');
    });
  });
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.getReset = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  User
    .findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires').gt(Date.now())
    .exec((err, user) => {
      if (err) { return next(err); }
      if (!user) {
        req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
        return res.redirect('/forgot');
      }
      res.render('account/reset', {
        title: 'Password Reset'
      });
    });
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postReset = (req, res, next) => {
  req.assert('password', 'Password must be at least 4 characters long.').len(4);
  req.assert('confirm', 'Passwords must match.').equals(req.body.password);

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('back');
  }

  const resetPassword = () =>
    User
      .findOne({ passwordResetToken: req.params.token })
      .where('passwordResetExpires').gt(Date.now())
      .then((user) => {
        if (!user) {
          req.flash('errors', { msg: 'Password reset token is invalid or has expired.' });
          return res.redirect('back');
        }
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        return user.save().then(() => new Promise((resolve, reject) => {
          req.logIn(user, (err) => {
            if (err) { return reject(err); }
            resolve(user);
          });
        }));
      });

  const sendResetPasswordEmail = (user) => {
    if (!user) { return; }
    let transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: process.env.SENDGRID_USER,
        pass: process.env.SENDGRID_PASSWORD
      }
    });
    const mailOptions = {
      to: user.email,
      from: 'hackathon@starter.com',
      subject: 'Your Hackathon Starter password has been changed',
      text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
    };
    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('success', { msg: 'Success! Your password has been changed.' });
      })
      .catch((err) => {
        if (err.message === 'self signed certificate in certificate chain') {
          console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
          transporter = nodemailer.createTransport({
            service: 'SendGrid',
            auth: {
              user: process.env.SENDGRID_USER,
              pass: process.env.SENDGRID_PASSWORD
            },
            tls: {
              rejectUnauthorized: false
            }
          });
          return transporter.sendMail(mailOptions)
            .then(() => {
              req.flash('success', { msg: 'Success! Your password has been changed.' });
            });
        }
        console.log('ERROR: Could not send password reset confirmation email after security downgrade.\n', err);
        req.flash('warning', { msg: 'Your password has been changed, however we were unable to send you a confirmation email. We will be looking into it shortly.' });
        return err;
      });
  };

  resetPassword()
    .then(sendResetPasswordEmail)
    .then(() => { if (!res.finished) res.redirect('/'); })
    .catch(err => next(err));
};

/**
 * GET /forgot
 * Forgot Password page.
 */
exports.getForgot = (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('account/forgot', {
    title: 'Forgot Password'
  });
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgot = (req, res, next) => {
  req.assert('email', 'Please enter a valid email address.').isEmail();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false });

  const errors = req.validationErrors();

  if (errors) {
    req.flash('errors', errors);
    return res.redirect('/forgot');
  }

  const createRandomToken = randomBytesAsync(16)
    .then(buf => buf.toString('hex'));

  const setRandomToken = token =>
    User
      .findOne({ email: req.body.email })
      .then((user) => {
        if (!user) {
          req.flash('errors', { msg: 'Account with that email address does not exist.' });
        } else {
          user.passwordResetToken = token;
          user.passwordResetExpires = Date.now() + 3600000; // 1 hour
          user = user.save();
        }
        return user;
      });

  const sendForgotPasswordEmail = (user) => {
    if (!user) { return; }
    const token = user.passwordResetToken;
    let transporter = nodemailer.createTransport({
      service: 'SendGrid',
      auth: {
        user: process.env.SENDGRID_USER,
        pass: process.env.SENDGRID_PASSWORD
      }
    });
    const mailOptions = {
      to: user.email,
      from: 'hackathon@starter.com',
      subject: 'Reset your password on Hackathon Starter',
      text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        http://${req.headers.host}/reset/${token}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`
    };
    return transporter.sendMail(mailOptions)
      .then(() => {
        req.flash('info', { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
      })
      .catch((err) => {
        if (err.message === 'self signed certificate in certificate chain') {
          console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
          transporter = nodemailer.createTransport({
            service: 'SendGrid',
            auth: {
              user: process.env.SENDGRID_USER,
              pass: process.env.SENDGRID_PASSWORD
            },
            tls: {
              rejectUnauthorized: false
            }
          });
          return transporter.sendMail(mailOptions)
            .then(() => {
              req.flash('info', { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
            });
        }
        console.log('ERROR: Could not send forgot password email after security downgrade.\n', err);
        req.flash('errors', { msg: 'Error sending the password reset message. Please try again shortly.' });
        return err;
      });
  };

  createRandomToken
    .then(setRandomToken)
    .then(sendForgotPasswordEmail)
    .then(() => res.redirect('/forgot'))
    .catch(next);
};
