/**
 * Module dependencies.
 */
var util = require('util'),
  OAuth2Strategy = require('passport-oauth2'),
  fetch = require('node-fetch');

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

  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params['client_id'] = this._clientId;
    params['secret'] = this._clientSecret;
    params['code'] = code;

    fetch(this._getAccessTokenUrl(), {
      method: 'POST',
      body: JSON.stringify(params),
      headers: {
        'Content-Type': 'application/json',
      },
    })
      .then(res => res.json())
      .then(res => callback(null, res.data, null, {}))
      .catch(error => callback(error));
  };
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
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, callback) {
  var self = this;

  fetch(this._apiURL + '/access-token/get-user', {
    method: 'POST',
    headers: {
      'x-access-token': accessToken,
    },
  })
    .then(res => res.json())
    .then(res => callback(null, self.formatProfile(res.data)))
    .catch(error => callback(error));
};

Strategy.prototype.formatProfile = function (user) {
  user.provider = 'makeflow';
  return user;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
