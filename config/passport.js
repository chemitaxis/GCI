var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;


var User = require('../models/User');

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Sign in with Email and Password
passport.use(new LocalStrategy({ usernameField: 'email' }, function(email, password, done) {
  User.findOne({ Email: email }, function(err, user) {
    if (!user) {
      return done(null, false, { msg: 'The email address ' + email + ' is not associated with any account. ' +
      'Double-check your email address and try again.' });
    }
    user.comparePassword(password, function(err, isMatch) {
      if (!isMatch) {
        return done(null, false, { msg: 'Invalid email or password' });
      }
      return done(null, user);
    });
  });
}));

// Sign in with Facebook
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_ID,
  clientSecret: process.env.FACEBOOK_SECRET,
  callbackURL: '/auth/facebook/callback',
  profileFields: ['name', 'email', 'gender', 'location'],
  passReqToCallback: true
}, function(req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({ Facebook: profile.id }, function(err, user) {
      if (user) {
        req.flash('error', { msg: 'There is already an existing account linked with Facebook that belongs to you.' });
        done(err);
      } else {
        User.findById(req.user.id, function(err, user) {
          user.Name = user.name || profile.name.givenName + ' ' + profile.name.familyName;
          user.Gender = user.gender || profile._json.gender;
          user.Picture = user.picture || 'https://graph.facebook.com/' + profile.id + '/picture?type=large';
          user.Facebook = profile.id;
          user.save(function(err) {
            req.flash('success', { msg: 'Your Facebook account has been linked.' });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({ Facebook: profile.id }, function(err, user) {
      if (user) {
        return done(err, user);
      }
      User.findOne({ Email: profile._json.email }, function(err, user) {
        if (user) {
          req.flash('error', { msg: user.email + ' is already associated with another account.' });
          done(err);
        } else {
          var newUser = new User({
            Name: profile.name.givenName + ' ' + profile.name.familyName,
            Email: profile._json.email,
            Gender: profile._json.gender,
            Location: profile._json.location && profile._json.location.name,
            Picture: 'https://graph.facebook.com/' + profile.id + '/picture?type=large',
            Facebook: profile.id
          });
          newUser.save(function(err) {
            done(err, newUser);
          });
        }
      });
    });
  }
}));

// Sign in with Google
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ID,
  clientSecret: process.env.GOOGLE_SECRET,
  callbackURL: '/auth/google/callback',
  passReqToCallback: true
}, function(req, accessToken, refreshToken, profile, done) {
  if (req.user) {
    User.findOne({ Google: profile.id }, function(err, user) {
      if (user) {
        req.flash('error', { msg: 'There is already an existing account linked with Google that belongs to you.' });
      } else {
        User.findById(req.user.id, function(err, user) {
          user.Name = user.name || profile.displayName;
          user.Gender = user.gender || profile._json.gender;
          user.Picture = user.picture || profile._json.image.url;
          user.Google = profile.id;
          user.save(function(err) {
            req.flash('success', { msg: 'Your Google account has been linked.' });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({ Google: profile.id }, function(err, user) {
      if (user) {
        return done(null, user);
      }
      User.findOne({ Email: profile.emails[0].value }, function(err, user) {
        if (user) {
          req.flash('error', { msg: user.email + ' is already associated with another account.' });
          done(err);
        } else {
          var newUser = new User({
            Name: profile.displayName,
            Email: profile.emails[0].value,
            Gender: profile._json.gender,
            Location: profile._json.location,
            Picture: profile._json.image.url,
            Google: profile.id
          });
          newUser.save(function(err) {
            done(err, newUser);
          });
        }
      });
    });
  }
}));

// Sign in with Twitter
passport.use(new TwitterStrategy({
  consumerKey: process.env.TWITTER_KEY,
  consumerSecret: process.env.TWITTER_SECRET,
  callbackURL: '/auth/twitter/callback',
  passReqToCallback: true
}, function(req, accessToken, tokenSecret, profile, done) {
  if (req.user) {
    User.findOne({ Twitter: profile.id }, function(err, user) {
      if (user) {
        req.flash('error', { msg: 'There is already an existing account linked with Twitter that belongs to you.' });
        done(err);
      } else {
        User.findById(req.user.id, function(err, user) {
          user.Name = user.name || profile.displayName;
          user.Location = user.location || profile._json.location;
          user.Picture = user.picture || profile._json.profile_image_url_https;
          user.Twitter = profile.id;
          user.save(function(err) {
            req.flash('success', { msg: 'Your Twitter account has been linked.' });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({ Twitter: profile.id }, function(err, existingUser) {
      if (existingUser) {
        return done(null, existingUser);
      }
      // Twitter does not provide an email address, but email is a required field in our User schema.
      // We can "fake" a Twitter email address as follows: username@twitter.com.
      // Ideally, it should be changed by a user to their real email address afterwards.
      // For example, after login, check if email contains @twitter.com, then redirect to My Account page,
      // and restrict user's page navigation until they update their email address.
      var newUser = new User({
        Name: profile.displayName,
        Email: profile.username + '@twitter.com',
        Location: profile._json.location,
        Picture: profile._json.profile_image_url_https,
        Twitter: profile.id
      });
      newUser.save(function(err) {
        done(err, newUser);
      });
    });
  }
}));
