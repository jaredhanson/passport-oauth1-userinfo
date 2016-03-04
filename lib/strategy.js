var util = require('util')
  , OAuth1Strategy = require('passport-oauth1')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth1').InternalOAuthError;


function Strategy(options, verify) {
  options = options || {};
  
  if (!options.userProfileURL) { throw new TypeError('OAuth 1.0-based strategy requires a userProfileURL option'); }

  OAuth1Strategy.call(this, options, verify);
  this._userProfileURL = options.userProfileURL;
}

util.inherits(Strategy, OAuth1Strategy);


Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  this._oauth.get(this._userProfileURL, token, tokenSecret, function (err, body, res) {
    var json;
    
    if (err) {
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }
    
    var profile = Profile.parse(json);
    profile._raw = body;
    profile._json = json;
    
    done(null, profile);
  });
}


module.exports = Strategy;
