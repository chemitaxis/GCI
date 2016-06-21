var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');
var passport = require('passport');
var User = require('../models/User');
var co = require('co-express');
var mongoose = require('mongoose');
var aspnetIdentityv3 = require('../utils/aspnet-identity-v3');
var aspnetIdentityv2 = require('aspnet-identity-pw');

/**
 * Login required middleware
 */
exports.ensureAuthenticated = function(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect('/login');
  }
};

/**
 * GET /login
 */
exports.loginGet = function(req, res) {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/login', {
    title: 'Log in'
  });
};

/**
 * POST /login
 */
exports.loginPost = co(function*(req, res, next) {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('email', 'Email cannot be blank').notEmpty();
  req.assert('password', 'Password cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/login');
  }
  mongoose.Promise = global.Promise;
  var email = req.body.email;

  var user = yield User.findOne({ Email: email }).exec();
  var identityHash = user.PasswordHash;
  if(user && identityHash){
    console.log('[aspnetIdentity] user "' + email + '" found.');

    var password = req.body.password;
    var src = new Buffer(identityHash, 'base64');
    var isValid = false;
    if(src.length===49){
      //v2
      isValid = aspnetIdentityv2.validatePassword(password, identityHash);
    } else{
      //v3
      isValid = aspnetIdentityv3.validatePassword(password, identityHash);
    }

    if(isValid){
      console.log('[aspnetIdentity] begin process to convert user to Node passport.js ...');

      user.name= user._doc.UserName,
      user.Password= password,
      user.PasswordHash = undefined;
      var logins= user._doc.Logins.toObject();
      if(logins){
        for (var i in logins) {
          var provider = logins[i].LoginProvider;
          if(provider==="Facebook" || provider==="Twitter" || provider==="Google" )
          {
            user[provider] = logins[i].ProviderKey;
          }

        }
      }

      yield user.save();

    } else{
      console.log('[aspnetIdentity] password incorrect');
    }

  }

  passport.authenticate('local', function(err, user, info) {
    if (!user) {
      req.flash('error', info);
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      res.redirect('/');
    });
  })(req, res, next);

});

/**
 * GET /logout
 */
exports.logout = function(req, res) {
  req.logout();
  res.redirect('/');
};

/**
 * GET /signup
 */
exports.signupGet = function(req, res) {
  if (req.user) {
    return res.redirect('/');
  }
  res.render('account/signup', {
    title: 'Sign up'
  });
};

/**
 * POST /signup
 */
exports.signupPost = function(req, res, next) {
  req.assert('name', 'Name cannot be blank').notEmpty();
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('email', 'Email cannot be blank').notEmpty();
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/signup');
  }

  User.findOne({ Email: req.body.email }, function(err, user) {
    if (user) {
      req.flash('error', { msg: 'The email address you have entered is already associated with another account.' });
      return res.redirect('/signup');
    }
    user = new User({
      Name: req.body.name,
      Email: req.body.email,
      Password: req.body.password
    });
    user.save(function(err) {
      req.logIn(user, function(err) {
        res.redirect('/');
      });
    });
  });
};

/**
 * GET /account
 */
exports.accountGet = function(req, res) {
  res.render('account/profile', {
    title: 'My Account'
  });
};

/**
 * PUT /account
 * Update profile information OR change password.
 */
exports.accountPut = function(req, res, next) {
  if ('password' in req.body) {
    req.assert('password', 'Password must be at least 4 characters long').len(4);
    req.assert('confirm', 'Passwords must match').equals(req.body.password);
  } else {
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('email', 'Email cannot be blank').notEmpty();
    req.sanitize('email').normalizeEmail({ remove_dots: false });
  }

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/account');
  }

  User.findById(req.user.id, function(err, user) {
    if ('password' in req.body) {
      user.Password = req.body.password;
    } else {
      user.Email = req.body.email;
      user.Name = req.body.name;
      user.Gender = req.body.gender;
      user.Location = req.body.location;
      user.Website = req.body.website;
    }
    user.save(function(err) {
      if ('password' in req.body) {
        req.flash('success', { msg: 'Your password has been changed.' });
      } else if (err && err.code === 11000) {
        req.flash('error', { msg: 'The email address you have entered is already associated with another account.' });
      } else {
        req.flash('success', { msg: 'Your profile information has been updated.' });
      }
      res.redirect('/account');
    });
  });
};

/**
 * DELETE /account
 */
exports.accountDelete = function(req, res, next) {
  User.remove({ _id: req.user.id }, function(err) {
    req.logout();
    req.flash('info', { msg: 'Your account has been permanently deleted.' });
    res.redirect('/');
  });
};

/**
 * GET /unlink/:provider
 */
exports.unlink = function(req, res, next) {
  User.findById(req.user.id, function(err, user) {
    switch (req.params.provider) {
      case 'facebook':
        user.Facebook = undefined;
        break;
      case 'google':
        user.Google = undefined;
        break;
      case 'twitter':
        user.Twitter = undefined;
        break;
      case 'vk':
        user.vk = undefined;
        break;
      default:
        req.flash('error', { msg: 'Invalid OAuth Provider' });
        return res.redirect('/account');
    }
    user.save(function(err) {
      req.flash('success', { msg: 'Your account has been unlinked.' });
      res.redirect('/account');
    });
  });
};

/**
 * GET /forgot
 */
exports.forgotGet = function(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('account/forgot', {
    title: 'Forgot Password'
  });
};

/**
 * POST /forgot
 */
exports.forgotPost = function(req, res, next) {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('email', 'Email cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ remove_dots: false });

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('/forgot');
  }

  async.waterfall([
    function(done) {
      crypto.randomBytes(16, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ Email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', { msg: 'The email address ' + req.body.email + ' is not associated with any account.' });
          return res.redirect('/forgot');
        }
        user.PasswordResetToken = token;
        user.PasswordResetExpires = Date.now() + 3600000; // expire in 1 hour
        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var transporter = nodemailer.createTransport({
        service: 'Mailgun',
        auth: {
          user: process.env.MAILGUN_USERNAME,
          pass: process.env.MAILGUN_PASSWORD
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'support@yourdomain.com',
        subject: '✔ Reset your password on Mega Boilerplate',
        text: 'You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n' +
        'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
        'http://' + req.headers.host + '/reset/' + token + '\n\n' +
        'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('info', { msg: 'An email has been sent to ' + user.email + ' with further instructions.' });
        res.redirect('/forgot');
      });
    }
  ]);
};

/**
 * GET /reset
 */
exports.resetGet = function(req, res) {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  User.findOne({ passwordResetToken: req.params.token })
    .where('passwordResetExpires').gt(Date.now())
    .exec(function(err, user) {
      if (!user) {
        req.flash('error', { msg: 'Password reset token is invalid or has expired.' });
        return res.redirect('/forgot');
      }
      res.render('account/reset', {
        title: 'Password Reset'
      });
    });
};

/**
 * POST /reset
 */
exports.resetPost = function(req, res, next) {
  req.assert('password', 'Password must be at least 4 characters long').len(4);
  req.assert('confirm', 'Passwords must match').equals(req.body.password);

  var errors = req.validationErrors();

  if (errors) {
    req.flash('error', errors);
    return res.redirect('back');
  }

  async.waterfall([
    function(done) {
      User.findOne({ passwordResetToken: req.params.token })
        .where('passwordResetExpires').gt(Date.now())
        .exec(function(err, user) {
          if (!user) {
            req.flash('error', { msg: 'Password reset token is invalid or has expired.' });
            return res.redirect('back');
          }
          user.password = req.body.password;
          user.passwordResetToken = undefined;
          user.passwordResetExpires = undefined;
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        });
    },
    function(user, done) {
      var transporter = nodemailer.createTransport({
        service: 'Mailgun',
        auth: {
          user: process.env.MAILGUN_USERNAME,
          pass: process.env.MAILGUN_PASSWORD
        }
      });
      var mailOptions = {
        from: 'support@yourdomain.com',
        to: user.email,
        subject: 'Your Mega Boilerplate password has been changed',
        text: 'Hello,\n\n' +
        'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('success', { msg: 'Your password has been changed successfully.' });
        res.redirect('/account');
      });
    }
  ]);
};
