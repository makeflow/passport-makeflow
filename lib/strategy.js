/**
 * Module dependencies.
 */
var util = require('util'),
  OAuth2Strategy = require('passport-oauth2'),
  InternalOAuthError = require('passport-oauth2').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Makeflow authentication strategy authenticates requests by delegating to
 * Makeflow using the OAuth 2.0 protocol.
 *
 *
 * Options:
 *   - `clientID`      your Makeflow application's Client ID
 *   - `clientSecret`  your Makeflow application's Client Secret
 *   - `callbackURL`   URL to which Makeflow will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                       'task:create','task:update','task:send-message','procedure:create','procedure:update','user:match','user:info', or none.
 *
 * Examples:
 *
 *     passport.use(new MakeflowStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/makeflow/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL =
    options.authorizationURL || 'https://www.makeflow.com/api/oauth/authorize';
  options.tokenURL =
    options.tokenURL || 'https://www.makeflow.com/api/oauth/get-access-token';
  options.customHeaders = options.customHeaders || {};
  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] =
      options.userAgent || 'passport-makeflow';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'makeflow';
  this._apiURL = options.apiURL || 'https://www.makeflow.com/api/v1';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Makeflow.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `makeflow`
 *   - `id`               the user's Makeflow ID
 *   - `username`         the user's Makeflow username
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on Makeflow
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, callback) {
  var self = this;
  this._oauth2.getProtectedResource(
    this._apiURL + '/user/get-info',
    accessToken,
    function (err, body) {
      if (err) return callback(new InternalOAuthError('', err));

      try {
        callback(null, self.formatProfile(JSON.parse(body))); // this is different with raw.
      } catch (e) {
        callback(e);
      }
    },
  );
};

Strategy.prototype.formatProfile = function (raw) {
  var user = {};
  user.provider = 'makeflow';
  user.id = raw.id;
  user.displayName = raw.username;
  user._raw = raw;
  user._json = raw;

  return user;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
