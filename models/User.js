var crypto = require('crypto');
var bcrypt = require('bcrypt-nodejs');
var mongoose = require('mongoose');

var schemaOptions = {
  timestamps: true,
  toJSON: {
    virtuals: true
  }
};



var userSchema = new mongoose.Schema({
  Name: String,
  Email: { type: String, unique: true},
  Password: String,
  PasswordResetToken: String,
  PasswordResetExpires: Date,
  Gender: String,
  Location: String,
  Website: String,
  Picture: String,
  Facebook: String,
  Twitter: String,
  Google: String,
  vk: String,
  UserName: String,
  TypeSubscription: Number,
  Confirmed: Boolean,
  Photo: String,
  LastLogin: Date,
  DateRegister: Date,
  PasswordHash: String,
  Logins:Array
}, schemaOptions);

userSchema.pre('save', function(next) {
  var user = this;
  if (!user.isModified('Password')) { return next(); }
  bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(user.Password, salt, null, function(err, hash) {
      user.Password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(password, cb) {
  bcrypt.compare(password, this.Password, function(err, isMatch) {
    cb(err, isMatch);
  });
};

userSchema.virtual('gravatar').get(function() {
  if (!this.get('Email')) {
    return 'https://gravatar.com/avatar/?s=200&d=retro';
  }
  var md5 = crypto.createHash('md5').update(this.get('Email')).digest('hex');
  return 'https://gravatar.com/avatar/' + md5 + '?s=200&d=retro';
});

var User = mongoose.model('User', userSchema);

module.exports = User;
