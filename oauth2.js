/**
 * Module dependencies.
 */
var jwt = require('jsonwebtoken')
var OAuth2Strategy = require("passport-oauth2")
var InternalOAuthError = OAuth2Strategy.InternalOAuthError


/**
 * `Strategy` constructor.
 *
 * The Twitch authentication strategy authenticates requests by delegating to
 * Twitch using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Twitch application"s client id
 *   - `clientSecret`  your Twitch application"s client secret
 *   - `callbackURL`   URL to which Twitch will redirect the user after granting authorization
 *   - `pem`           Signing certificate used for decoding a user's OIDC token
 *
 * Examples:
 *
 *     passport.use(new TwitchStrategy({
 *         clientID: "123-456-789",
 *         clientSecret: "shhh-its-a-secret"
 *         callbackURL: "https://www.example.net/auth/twitch/callback"
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user)
 *         })
 *       }
 *     ))
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
class Strategy extends OAuth2Strategy {
    constructor(options, verify) {
        options = options || {}
        options.authorizationURL = options.authorizationURL || "https://id.twitch.tv/oauth2/authorize"
        options.tokenURL = options.tokenURL || "https://id.twitch.tv/oauth2/token"
        options.parseIdToken = !!options.pem
        
        super(options, verify)

        this.name = "twitch"
        this.pem = options.pem

        this._oauth2.setAuthMethod("Bearer")
        this._oauth2.useAuthorizationHeaderforGET(true)
    }

    userProfile(token, done) {
        if (!this.pem) return done(null, {})

        jwt.verify(token, this.pem, done)
    }

    authorizationParams(options) {
        var params = {}
        if (typeof options.forceVerify !== "undefined") {
            params.force_verify = !!options.forceVerify
        }
        return params
    }
}

module.exports = Strategy
