'use strict';

const nconf = require('nconf');
const validator = require('validator');

const meta = require('../meta');
const user = require('../user');
const plugins = require('../plugins');
const privileges = require('../privileges');
const helpers = require('./helpers');
const passport = require('passport');
const Controllers = module.exports;

Controllers.ping = require('./ping');
Controllers.home = require('./home');
Controllers.topics = require('./topics');
Controllers.posts = require('./posts');
Controllers.categories = require('./categories');
Controllers.category = require('./category');
Controllers.unread = require('./unread');
Controllers.recent = require('./recent');
Controllers.popular = require('./popular');
Controllers.top = require('./top');
Controllers.tags = require('./tags');
Controllers.search = require('./search');
Controllers.user = require('./user');
Controllers.users = require('./users');
Controllers.groups = require('./groups');
Controllers.accounts = require('./accounts');
Controllers.authentication = require('./authentication');
Controllers.api = require('./api');
Controllers.admin = require('./admin');
Controllers.globalMods = require('./globalmods');
Controllers.mods = require('./mods');
Controllers.sitemap = require('./sitemap');
Controllers.osd = require('./osd');
Controllers['404'] = require('./404');
Controllers.errors = require('./errors');
Controllers.composer = require('./composer');
//const controllers = require('./controllers');
Controllers.write = require('./write');

Controllers.reset = async function (req, res) {
	if (meta.config['password:disableEdit']) {
		return helpers.notAllowed(req, res);
	}

	res.locals.metaTags = {
		...res.locals.metaTags,
		name: 'robots',
		content: 'noindex',
	};

	const renderReset = function (code, valid) {
		res.render('reset_code', {
			valid: valid,
			displayExpiryNotice: req.session.passwordExpired,
			code: code,
			minimumPasswordLength: meta.config.minimumPasswordLength,
			minimumPasswordStrength: meta.config.minimumPasswordStrength,
			breadcrumbs: helpers.buildBreadcrumbs([
				{
					text: '[[reset_password:reset_password]]',
					url: '/reset',
				},
				{
					text: '[[reset_password:update_password]]',
				},
			]),
			title: '[[pages:reset]]',
		});
		delete req.session.passwordExpired;
	};

	if (req.params.code) {
		req.session.reset_code = req.params.code;
	}

	if (req.session.reset_code) {
		// Validate and save to local variable before removing from session
		const valid = await user.reset.validate(req.session.reset_code);
		renderReset(req.session.reset_code, valid);
		delete req.session.reset_code;
	} else {
		res.render('reset', {
			code: null,
			breadcrumbs: helpers.buildBreadcrumbs([{
				text: '[[reset_password:reset_password]]',
			}]),
			title: '[[pages:reset]]',
		});
	}
};

Controllers.login = async function (req, res) {
	//console.log('aaaaa',req.params.username);
	const data = { loginFormEntry: [] };
	const loginStrategies = require('../routes/authentication').getLoginStrategies();
	const registrationType = meta.config.registrationType || 'normal';
	const allowLoginWith = (meta.config.allowLoginWith || 'username-email');

	let errorText;
	if (req.query.error === 'csrf-invalid') {
		errorText = '[[error:csrf-invalid]]';
	} else if (req.query.error) {
		errorText = validator.escape(String(req.query.error));
	}

	if (req.headers['x-return-to']) {
		req.session.returnTo = req.headers['x-return-to'];
	}

	// Occasionally, x-return-to is passed a full url.
	req.session.returnTo = req.session.returnTo && req.session.returnTo.replace(nconf.get('base_url'), '').replace(nconf.get('relative_path'), '');

	data.alternate_logins = loginStrategies.length > 0;
	data.authentication = loginStrategies;
	data.allowRegistration = registrationType === 'normal';
	data.allowLoginWith = `[[login:${allowLoginWith}]]`;
	data.breadcrumbs = helpers.buildBreadcrumbs([{
		text: '[[global:login]]',
	}]);
	data.error = req.flash('error')[0] || errorText;
	data.title = '[[pages:login]]';
	data.allowPasswordReset = !meta.config['password:disableEdit'];

	const hasLoginPrivilege = await privileges.global.canGroup('local:login', 'registered-users');
	data.allowLocalLogin = hasLoginPrivilege || parseInt(req.query.local, 10) === 1;

	if (!data.allowLocalLogin && !data.allowRegistration && data.alternate_logins && data.authentication.length === 1) {
		return helpers.redirect(res, { external: data.authentication[0].url });
	}

	if (req.loggedIn) {
		const userData = await user.getUserFields(req.uid, ['username', 'email']);
		data.username = allowLoginWith === 'email' ? userData.email : userData.username;
		data.alternate_logins = false;
	}
	
	res.render('login', data);
};


// Controllers.loginUsername = async function (req, res) {

// req.body= {"username":"ghanshyam",
// "password":"123456",
// "remember":"on",
// "_csrf":"xOtszWpq-VX73hpSGR38C4mxSc63BqtyW5fs",
// "noscript": false
// }

// console.log('req.body',req.body);
// 	//return;

// 	let { strategy } = await plugins.hooks.fire('filter:login.override', { req, strategy: 'local' });
// 	if (!passport._strategy(strategy)) {
// 		winston.error(`[auth/override] Requested login strategy "${strategy}" not found, reverting back to local login strategy.`);
// 		strategy = 'local';
// 	}

// 	if (plugins.hooks.hasListeners('action:auth.overrideLogin')) {
// 		return continueLogin(strategy, req, res, next);
// 	}

// 	const loginWith = meta.config.allowLoginWith || 'username-email';
// 	req.body.username = req.body.username.trim();
// 	const errorHandler = res.locals.noScriptErrors || helpers.noScriptErrors;
// 	try {
// 		await plugins.hooks.fire('filter:login.check', { req: req, res: res, userData: req.body });
// 	} catch (err) {
// 		return errorHandler(req, res, err.message, 403);
// 	}
// 	try {
// 		const isEmailLogin = loginWith.includes('email') && req.body.username && utils.isEmailValid(req.body.username);
// 		const isUsernameLogin = loginWith.includes('username') && !validator.isEmail(req.body.username);
// 		if (isEmailLogin) {
// 			const username = await user.getUsernameByEmail(req.body.username);
// 			if (username !== '[[global:guest]]') {
// 				req.body.username = username;
// 			}
// 		}
// 		if (isEmailLogin || isUsernameLogin) {
// 			continueLogin(strategy, req, res, next);
// 		} else {
// 			errorHandler(req, res, `[[error:wrong-login-type-${loginWith}]]`, 400);
// 		}
// 	} catch (err) {
// 		return errorHandler(req, res, err.message, 500);
// 	}

// }

// function continueLogin(strategy, req, res, next) {
// 	passport.authenticate(strategy, async (err, userData, info) => {

// 		console.log('userData',userData,'info',info);
// 		if (err) {
// 			plugins.hooks.fire('action:login.continue', { req, strategy, userData, error: err });
// 			return helpers.noScriptErrors(req, res, err.data || err.message, 403);
// 		}

// 		if (!userData) {
// 			if (info instanceof Error) {
// 				info = info.message;
// 			} else if (typeof info === 'object') {
// 				info = '[[error:invalid-username-or-password]]';
// 			}

// 			plugins.hooks.fire('action:login.continue', { req, strategy, userData, error: new Error(info) });
// 			return helpers.noScriptErrors(req, res, info, 403);
// 		}

// 		// Alter user cookie depending on passed-in option
// 		if (req.body.remember === 'on') {
// 			const duration = meta.getSessionTTLSeconds() * 1000;
// 			req.session.cookie.maxAge = duration;
// 			req.session.cookie.expires = new Date(Date.now() + duration);
// 		} else {
// 			req.session.cookie.maxAge = false;
// 			req.session.cookie.expires = false;
// 		}

// 		plugins.hooks.fire('action:login.continue', { req, strategy, userData, error: null });

// 		if (userData.passwordExpiry && userData.passwordExpiry < Date.now()) {
// 			winston.verbose(`[auth] Triggering password reset for uid ${userData.uid} due to password policy`);
// 			req.session.passwordExpired = true;

// 			const code = await user.reset.generate(userData.uid);
// 			(res.locals.redirectAfterLogin || redirectAfterLogin)(req, res, `${nconf.get('relative_path')}/reset/${code}`);
// 		} else {
// 			delete req.query.lang;
// 			await authenticationController.doLogin(req, userData.uid);
// 			let destination;
// 			if (req.session.returnTo) {
// 				destination = req.session.returnTo.startsWith('http') ?
// 					req.session.returnTo :
// 					nconf.get('relative_path') + req.session.returnTo;
// 				delete req.session.returnTo;
// 			} else {
// 				destination = `${nconf.get('relative_path')}/`;
// 			}

// 			(res.locals.redirectAfterLogin || redirectAfterLogin)(req, res, destination);
// 		}
// 	})(req, res, next);
// }

// function redirectAfterLogin(req, res, destination) {

// 	console.log('destination',destination);
// 	if (req.body.noscript === 'true') {
// 		res.redirect(`${destination}?loggedin`);
// 	} else {
// 		res.status(200).send({
// 			next: destination,
// 		});
// 	}
// }

Controllers.register = async function (req, res, next) {
	const registrationType = meta.config.registrationType || 'normal';

	if (registrationType === 'disabled') {
		return setImmediate(next);
	}

	let errorText;
	const returnTo = (req.headers['x-return-to'] || '').replace(nconf.get('base_url') + nconf.get('relative_path'), '');
	if (req.query.error === 'csrf-invalid') {
		errorText = '[[error:csrf-invalid]]';
	}
	try {
		if (registrationType === 'invite-only' || registrationType === 'admin-invite-only') {
			try {
				await user.verifyInvitation(req.query);
			} catch (e) {
				return res.render('400', {
					error: e.message,
				});
			}
		}

		if (returnTo) {
			req.session.returnTo = returnTo;
		}

		const loginStrategies = require('../routes/authentication').getLoginStrategies();
		res.render('register', {
			'register_window:spansize': loginStrategies.length ? 'col-md-6' : 'col-md-12',
			alternate_logins: !!loginStrategies.length,
			authentication: loginStrategies,

			minimumUsernameLength: meta.config.minimumUsernameLength,
			maximumUsernameLength: meta.config.maximumUsernameLength,
			minimumPasswordLength: meta.config.minimumPasswordLength,
			minimumPasswordStrength: meta.config.minimumPasswordStrength,
			breadcrumbs: helpers.buildBreadcrumbs([{
				text: '[[register:register]]',
			}]),
			regFormEntry: [],
			error: req.flash('error')[0] || errorText,
			title: '[[pages:register]]',
		});
	} catch (err) {
		next(err);
	}
};

Controllers.registerInterstitial = async function (req, res, next) {
	if (!req.session.hasOwnProperty('registration')) {
		return res.redirect(`${nconf.get('relative_path')}/register`);
	}
	try {
		const data = await plugins.hooks.fire('filter:register.interstitial', {
			req,
			userData: req.session.registration,
			interstitials: [],
		});

		if (!data.interstitials.length) {
			// No interstitials, redirect to home
			const returnTo = req.session.returnTo || req.session.registration.returnTo;
			delete req.session.registration;
			return helpers.redirect(res, returnTo || '/');
		}

		const errors = req.flash('errors');
		const renders = data.interstitials.map(
			interstitial => req.app.renderAsync(interstitial.template, { ...interstitial.data || {}, errors })
		);
		const sections = await Promise.all(renders);

		res.render('registerComplete', {
			title: '[[pages:registration-complete]]',
			register: data.userData.register,
			sections,
			errors,
		});
	} catch (err) {
		next(err);
	}
};

Controllers.confirmEmail = async (req, res, next) => {
	try {
		await user.email.confirmByCode(req.params.code, req.session.id);
	} catch (e) {
		if (e.message === '[[error:invalid-data]]') {
			return next();
		}

		throw e;
	}

	res.render('confirm', {
		title: '[[pages:confirm]]',
	});
};

Controllers.robots = function (req, res) {
	res.set('Content-Type', 'text/plain');

	if (meta.config['robots:txt']) {
		res.send(meta.config['robots:txt']);
	} else {
		res.send(`${'User-agent: *\n' +
			'Disallow: '}${nconf.get('relative_path')}/admin/\n` +
			`Disallow: ${nconf.get('relative_path')}/reset/\n` +
			`Disallow: ${nconf.get('relative_path')}/compose\n` +
			`Sitemap: ${nconf.get('url')}/sitemap.xml`);
	}
};

Controllers.manifest = async function (req, res) {
	const manifest = {
		name: meta.config.title || 'NodeBB',
		short_name: meta.config['title:short'] || meta.config.title || 'NodeBB',
		start_url: nconf.get('url'),
		display: 'standalone',
		orientation: 'portrait',
		theme_color: meta.config.themeColor || '#ffffff',
		background_color: meta.config.backgroundColor || '#ffffff',
		icons: [],
	};

	if (meta.config['brand:touchIcon']) {
		manifest.icons.push({
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-36.png`,
			sizes: '36x36',
			type: 'image/png',
			density: 0.75,
		}, {
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-48.png`,
			sizes: '48x48',
			type: 'image/png',
			density: 1.0,
		}, {
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-72.png`,
			sizes: '72x72',
			type: 'image/png',
			density: 1.5,
		}, {
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-96.png`,
			sizes: '96x96',
			type: 'image/png',
			density: 2.0,
		}, {
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-144.png`,
			sizes: '144x144',
			type: 'image/png',
			density: 3.0,
		}, {
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-192.png`,
			sizes: '192x192',
			type: 'image/png',
			density: 4.0,
		}, {
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-512.png`,
			sizes: '512x512',
			type: 'image/png',
			density: 10.0,
		});
	}


	if (meta.config['brand:maskableIcon']) {
		manifest.icons.push({
			src: `${nconf.get('relative_path')}/assets/uploads/system/maskableicon-orig.png`,
			type: 'image/png',
			purpose: 'maskable',
		});
	} else if (meta.config['brand:touchIcon']) {
		manifest.icons.push({
			src: `${nconf.get('relative_path')}/assets/uploads/system/touchicon-orig.png`,
			type: 'image/png',
			purpose: 'maskable',
		});
	}

	const data = await plugins.hooks.fire('filter:manifest.build', {
		req: req,
		res: res,
		manifest: manifest,
	});
	res.status(200).json(data.manifest);
};

Controllers.outgoing = function (req, res, next) {
	const url = req.query.url || '';
	const allowedProtocols = [
		'http', 'https', 'ftp', 'ftps', 'mailto', 'news', 'irc', 'gopher',
		'nntp', 'feed', 'telnet', 'mms', 'rtsp', 'svn', 'tel', 'fax', 'xmpp', 'webcal',
	];
	const parsed = require('url').parse(url);

	if (!url || !parsed.protocol || !allowedProtocols.includes(parsed.protocol.slice(0, -1))) {
		return next();
	}

	res.render('outgoing', {
		outgoing: validator.escape(String(url)),
		title: meta.config.title,
		breadcrumbs: helpers.buildBreadcrumbs([{
			text: '[[notifications:outgoing_link]]',
		}]),
	});
};

Controllers.termsOfUse = async function (req, res, next) {
	if (!meta.config.termsOfUse) {
		return next();
	}
	const termsOfUse = await plugins.hooks.fire('filter:parse.post', {
		postData: {
			content: meta.config.termsOfUse || '',
		},
	});
	res.render('tos', {
		termsOfUse: termsOfUse.postData.content,
	});
};
