var SteamTotp = require('steam-totp');
var SteamCommunity = require('../index.js');

var ETwoFactorTokenType = {
	"None": 0,                  // No token-based two-factor authentication
	"ValveMobileApp": 1,        // Tokens generated using Valve's special charset (5 digits, alphanumeric)
	"ThirdParty": 2             // Tokens generated using literally everyone else's standard charset (6 digits, numeric). This is disabled.
};

SteamCommunity.prototype.enableTwoFactor = function(callback) {
	var self = this;

	this.getWebApiOauthToken(function(err, token) {
		if(err) {
			callback(err);
			return;
		}

		self.httpRequestPost({
			"uri": "https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v1/",
			"form": {
				"steamid": self.steamID.getSteamID64(),
				"access_token": token,
				"authenticator_time": Math.floor(Date.now() / 1000),
				"authenticator_type": ETwoFactorTokenType.ValveMobileApp,
				"device_identifier": SteamTotp.getDeviceID(self.steamID),
				"sms_phone_id": "1"
			},
			"json": true
		}, function(err, response, body) {
			if (err) {
				callback(err);
				return;
			}

			if(!body.response) {
				callback(new Error("Malformed response"));
				return;
			}

			if(body.response.status != 1) {
				var error = new Error("Error " + body.response.status);
				error.eresult = body.response.status;
				callback(error);
				return;
			}

			callback(null, body.response);
		}, "steamcommunity");
	});
};

SteamCommunity.prototype.finalizeTwoFactor = function(secret, activationCode, callback) {
	var attemptsLeft = 30;
	var diff = 0;

	var self = this;
	this.getWebApiOauthToken(function(err, token) {
		if(err) {
			callback(err);
			return;
		}

		SteamTotp.getTimeOffset(function(err, offset, latency) {
			if (err) {
				callback(err);
				return;
			}

			diff = offset;
			finalize(token);
		});
	});

	function finalize(token) {
		var code = SteamTotp.generateAuthCode(secret, diff);

		self.httpRequestPost({
			"uri": "https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v1/",
			"form": {
				"steamid": self.steamID.getSteamID64(),
				"access_token": token,
				"authenticator_code": code,
				"authenticator_time": Math.floor(Date.now() / 1000),
				"activation_code": activationCode
			},
			"json": true
		}, function(err, response, body) {
			if (err) {
				callback(err);
				return;
			}

			if(!body.response) {
				callback(new Error("Malformed response"));
				return;
			}

			body = body.response;

			if(body.server_time) {
				diff = body.server_time - Math.floor(Date.now() / 1000);
			}

			if(body.status == 89) {
				callback(new Error("Invalid activation code"));
			} else if(body.want_more) {
				attemptsLeft--;
				diff += 30;

				finalize(token);
			} else if(!body.success) {
				callback(new Error("Error " + body.status));
			} else {
				callback(null);
			}
		}, "steamcommunity");
	}
};

SteamCommunity.prototype.disableTwoFactor = function(revocationCode, callback) {
	var self = this;

	this.getWebApiOauthToken(function(err, token) {
		if(err) {
			callback(err);
			return;
		}

		self.httpRequestPost({
			"uri": "https://api.steampowered.com/ITwoFactorService/RemoveAuthenticator/v1/",
			"form": {
				"steamid": self.steamID.getSteamID64(),
				"access_token": token,
				"revocation_code": revocationCode,
				"steamguard_scheme": 1
			},
			"json": true
		}, function(err, response, body) {
			if (err) {
				callback(err);
				return;
			}

			if(!body.response) {
				callback(new Error("Malformed response"));
				return;
			}

			if(!body.response.success) {
				callback(new Error("Request failed"));
				return;
			}

			// success = true means it worked
			callback(null);
		}, "steamcommunity");
	});
};

SteamCommunity.prototype.resetTwoFactor = function(phone, callback) {
	var self = this;

	self.httpRequestPost({
		"uri": "https://steamcommunity.com/login/getresetoptions/",
		"form": {
			"donotcache": Date.now()
		},
		"json": true
	}, (err, res, body) => {
		if (err) {
			callback(err);
			return;
		}

		if (body.success && body.success != SteamCommunity.EResult.OK) {
			let err = new Error(body.message || SteamCommunity.EResult[body.success]);
			err.eresult = err.code = body.success;
			callback(err);
			return;
		}

		if (!body.options || !body.options.sms || !body.options.sms.allowed) {
			callback(new Error("Malformed response"));
			return;
		}

		let lastDigits = body.options.sms.last_digits;

		console.log(body.options.sms);
		console.log(phone);
		if (phone.endsWith(lastDigits)) {
			self.httpRequestPost({
				"uri": "https://steamcommunity.com/login/startremovetwofactor/",
				"form": {
					"donotcache": Date.now()
				},
				"json": true
			}, (err, res, body) => {
				if (err) {
					callback(err);
					return;
				}

				if (body.success && body.success != SteamCommunity.EResult.OK) {
					let err = new Error(body.message || SteamCommunity.EResult[body.success]);
					err.eresult = err.code = body.success;
					callback(err);
					return;
				}

				callback(null, lastDigits);
			}, "steamcommunity");
		} else {
			callback(new Error("Phone number doesn't match"));
		}
	}, "steamcommunity");
};

SteamCommunity.prototype.finalizeResetTwoFactor = function(smscode, callback) {
	var self = this;

	self.httpRequestPost({
		"uri": "https://steamcommunity.com/login/removetwofactor/",
		"form": {
			"donotcache": Date.now(),
			"smscode": smscode,
			"reset": 1
		},
		"json": true
	}, (err, res, body) => {
		if (err) {
			callback(err);
			return;
		}

		if (body.success && body.success != SteamCommunity.EResult.OK) {
			let err = new Error(body.message || SteamCommunity.EResult[body.success]);
			err.eresult = err.code = body.success;
			callback(err);
			return;
		}

		if (!body.success) {
			console.log(body);
			callback(new Error("Failed"));
			return;
		}

		if (!body.replacement_token) {
			callback(new Error("Malformed response"));
			return;
		}

		let replacement_token = Buffer.from(body.replacement_token, 'base64').toString();
		callback(null, JSON.parse(replacement_token));
	}, "steamcommunity");
};
