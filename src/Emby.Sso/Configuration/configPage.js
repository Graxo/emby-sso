define(['baseView', 'loading', 'globalize', 'emby-input', 'emby-button', 'emby-checkbox', 'emby-scroller'], function (BaseView, loading, globalize) {
    'use strict';

    var pluginId = 'ad89f430-b0d0-4e9a-996d-c088f6961158';

    function showUrls(page, baseUrl) {
        var base = (baseUrl || '').replace(/[\/]+$/, '');
        page.querySelector('#redirectUri').value = base + '/sso/callback';
        page.querySelector('#startUrl').value = base + '/sso/start';
        page.querySelector('#pinUrl').value = base + '/sso/pin';
    }

    // The update area. Hidden unless the vendor has signed for something newer,
    // because a control that is always there and usually says "up to date" is a
    // control people stop reading.
    //
    // FAILS TOWARDS SHOWING NOTHING. If the check cannot be made - no network,
    // a stale session, no manifest published - the area stays hidden. The one
    // thing it must never do is offer an update it has not verified.
    function showUpdate(page) {
        var available = page.querySelector('#updateAvailable');
        var pending = page.querySelector('#restartPending');

        function show(info) {
            page.querySelector('#currentVersion').textContent = info.CurrentVersion || '';
            page.querySelector('#availableVersion').textContent = info.AvailableVersion || '';
            available.style.display = info.UpdateAvailable === true ? '' : 'none';
            pending.style.display = info.RestartPending === true ? '' : 'none';
        }

        ApiClient.getJSON(ApiClient.getUrl('sso/update')).then(show, function () {
            show({});
        });
    }

    function installUpdate(page) {
        var result = page.querySelector('#updateResult');

        result.textContent = 'Downloading and verifying...';
        loading.show();

        ApiClient.ajax({
            type: 'POST',
            url: ApiClient.getUrl('sso/update/install'),
            dataType: 'json'
        }).then(function (response) {
            loading.hide();

            // textContent, not innerHTML: a sentence, not markup.
            result.textContent = response.Message || '';

            if (response.Installed) {
                // Ask again rather than assuming: the answer now includes the
                // pending-restart banner, and the offer should disappear.
                showUpdate(page);
            }
        }).catch(function (err) {
            loading.hide();
            result.textContent = 'The update could not be completed. Nothing has been changed.';
            Dashboard.processErrorResponse(err);
        });
    }

    // Admin-only endpoint on this plugin's own service.
    //
    // TWO STATES, and the licensed one is deliberately almost empty: an
    // operator whose licence is fine has nothing to do on this part of the page
    // and should not have to read a screen of fields to establish that. When it
    // is not fine, everything needed to fix it is there instead.
    //
    // FAILS TOWARDS THE FULL FORM. If this call does not come back - the
    // endpoint is admin-only and could 401 on a session that has gone stale -
    // the page shows the buy-and-redeem side rather than "Active", because
    // claiming a licence is fine on no evidence is the one wrong answer.
    function showActivation(page) {
        var active = page.querySelector('#licenceActive');
        var inactive = page.querySelector('#licenceInactive');

        function show(info) {
            var licensed = info.Licensed === true;

            active.style.display = licensed ? '' : 'none';
            inactive.style.display = licensed ? 'none' : '';

            var status = info.Status || 'Not activated';

            page.querySelector('#licenceStatus').textContent = licensed && info.ExpiresUtc
                ? status + ' until ' + info.ExpiresUtc
                : status;

            page.querySelector('#licenceProblem').textContent = licensed ? '' : status;
            page.querySelector('#serverId').value = info.ServerId || '';

            // The stored licence, shown read-only. Read from the hidden field
            // rather than from the response: that field is what Save writes, so
            // showing anything else would let the two disagree.
            page.querySelector('#licenceKeyShown').value = page.querySelector('#licenceKey').value;

            // Both zero means this licence was pasted in by hand rather than
            // redeemed, so there is no allowance to report. "0 of 0" would look
            // like an exhausted code, which is the opposite of the truth.
            var allowed = info.ActivationsAllowed || 0;

            page.querySelector('#activationsContainer').style.display = allowed > 0 ? '' : 'none';
            page.querySelector('#activationsUsed').textContent =
                (info.ActivationsUsed || 0) + ' / ' + allowed;

            // No buy link when there is no address to send anybody to - a
            // control that goes nowhere is worse than no control. The address
            // is only known once this call answers, because it carries this
            // server's id, which is why the href starts empty.
            page.querySelector('#buyButton').href = info.BuyUrl || '#';
            page.querySelector('#buyContainer').style.display = info.BuyUrl ? '' : 'none';
        }

        ApiClient.getJSON(ApiClient.getUrl('sso/activation')).then(show, function () {
            show({});
        });
    }

    function activate(page) {
        var codeField = page.querySelector('#redemptionCode');
        var result = page.querySelector('#activationResult');
        var code = codeField.value.trim();

        if (!code) {
            result.textContent = 'Enter the redemption code you were given.';
            return;
        }

        result.textContent = 'Contacting the licensing service...';
        loading.show();

        // The code goes in the body, never in the URL: it is a bearer secret,
        // and a query string is written to access logs and proxy logs.
        ApiClient.ajax({
            type: 'POST',
            url: ApiClient.getUrl('sso/activate'),
            data: JSON.stringify({ Code: code }),
            contentType: 'application/json',
            dataType: 'json'
        }).then(function (response) {
            loading.hide();

            // textContent, not innerHTML: this is a sentence, not markup.
            result.textContent = response.Message || '';

            if (response.Activated) {
                // The server has already stored it. Filling the field in too
                // stops a later Save from writing the stale field value back
                // over the licence that was just activated.
                page.querySelector('#licenceKey').value = response.LicenceKey || '';
                codeField.value = '';

                // The page said "Not activated" a moment ago. Ask again rather
                // than assuming: this re-reads the same check the sign-in path
                // makes, so the page cannot start claiming Active on the
                // strength of a response it has not verified.
                showActivation(page);
            }
        }).catch(function (err) {
            loading.hide();
            result.textContent = 'The activation request could not be completed.';
            Dashboard.processErrorResponse(err);
        });
    }

    function loadPage(page, config) {
        page.querySelector('#issuerUrl').value = config.IssuerUrl || '';
        page.querySelector('#clientId').value = config.ClientId || '';
        page.querySelector('#clientSecret').value = config.ClientSecret || '';
        page.querySelector('#scopes').value = config.Scopes || 'openid profile email';
        page.querySelector('#embyPublicBaseUrl').value = config.EmbyPublicBaseUrl || '';
        page.querySelector('#usernameClaim').value = config.UsernameClaim || 'preferred_username';
        page.querySelector('#enableDirectGrant').checked = config.EnableDirectGrant === true;
        page.querySelector('#enablePinSignIn').checked = config.EnablePinSignIn === true;
        page.querySelector('#allowInsecureHttp').checked = config.AllowInsecureHttp === true;
        page.querySelector('#allowPrivateNetworkProvider').checked = config.AllowPrivateNetworkProvider === true;
        page.querySelector('#requiredGroup').value = config.RequiredGroup || '';
        page.querySelector('#groupsClaim').value = config.GroupsClaim || 'groups';
        page.querySelector('#templateUserName').value = config.TemplateUserName || '';
        page.querySelector('#enableAutoCreate').checked = config.EnableAutoCreate === true;
        page.querySelector('#licenceKey').value = config.LicenceKey || '';
        page.querySelector('#activationResult').textContent = '';
        showUrls(page, config.EmbyPublicBaseUrl);
        showActivation(page);
        showUpdate(page);

        loading.hide();
    }

    function handleError(err) {
        loading.hide();
        Dashboard.processErrorResponse(err);
    }

    function getConfig() {
        return ApiClient.getPluginConfiguration(pluginId);
    }

    function onSubmit(e) {
        e.preventDefault();

        loading.show();

        var form = this;

        getConfig().then(function (config) {
            config.IssuerUrl = form.querySelector('#issuerUrl').value.trim();
            config.ClientId = form.querySelector('#clientId').value.trim();
            config.ClientSecret = form.querySelector('#clientSecret').value;
            config.Scopes = form.querySelector('#scopes').value.trim();
            config.EmbyPublicBaseUrl = form.querySelector('#embyPublicBaseUrl').value.trim();
            config.UsernameClaim = form.querySelector('#usernameClaim').value.trim();
            config.EnableDirectGrant = form.querySelector('#enableDirectGrant').checked;
            config.EnablePinSignIn = form.querySelector('#enablePinSignIn').checked;
            // The sign-in button was a placeholder for something Emby's web
            // client cannot render, so the checkbox is gone from the page.
            // Written as false rather than left alone: a setting that can no
            // longer be turned off must not stay on because somebody once
            // ticked it.
            config.EnableButtonInjection = false;
            config.AllowInsecureHttp = form.querySelector('#allowInsecureHttp').checked;
            config.AllowPrivateNetworkProvider = form.querySelector('#allowPrivateNetworkProvider').checked;
            config.RequiredGroup = form.querySelector('#requiredGroup').value.trim();
            config.GroupsClaim = form.querySelector('#groupsClaim').value.trim();
            config.TemplateUserName = form.querySelector('#templateUserName').value.trim();
            config.EnableAutoCreate = form.querySelector('#enableAutoCreate').checked;
            config.LicenceKey = form.querySelector('#licenceKey').value.trim();

            return ApiClient.updatePluginConfiguration(pluginId, config).then(function (result) {
                loading.hide();
                Dashboard.processPluginConfigurationUpdateResult(result);
                showUrls(form, config.EmbyPublicBaseUrl);
            });
        }).catch(handleError);

        // Disable default form submission
        return false;
    }

    function View(view, params) {
        BaseView.apply(this, arguments);

        view.querySelector('form').addEventListener('submit', onSubmit);

        view.querySelector('#activateButton').addEventListener('click', function () {
            activate(view);
        });

        // One handler for all three copy buttons. navigator.clipboard needs a
        // secure context, which the Emby dashboard over https is; the textarea
        // fallback covers a dashboard reached over plain http, where the modern
        // API is simply absent rather than failing.
        Array.prototype.forEach.call(view.querySelectorAll('.copyButton'), function (button) {
            button.addEventListener('click', function () {
                var field = view.querySelector('#' + button.dataset.copy);
                var result = view.querySelector('#copyResult');

                function done(ok) {
                    result.textContent = ok ? 'Copied.' : 'Could not copy - select the text instead.';
                }

                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(field.value).then(function () {
                        done(true);
                    }, function () {
                        done(false);
                    });

                    return;
                }

                // A disabled input cannot be selected, so copy through a
                // throwaway one rather than enabling the real field.
                var scratch = document.createElement('textarea');

                scratch.value = field.value;
                scratch.setAttribute('readonly', '');
                scratch.style.position = 'absolute';
                scratch.style.left = '-9999px';
                document.body.appendChild(scratch);
                scratch.select();

                var ok = false;

                try {
                    ok = document.execCommand('copy');
                } catch (e) {
                    ok = false;
                }

                document.body.removeChild(scratch);
                done(ok);
            });
        });

        view.querySelector('#updateButton').addEventListener('click', function () {
            installUpdate(view);
        });
    }

    Object.assign(View.prototype, BaseView.prototype);

    View.prototype.onResume = function (options) {
        BaseView.prototype.onResume.apply(this, arguments);

        loading.show();

        var page = this.view;

        getConfig().then(function (response) {
            loadPage(page, response);
        }).catch(handleError);
    };

    return View;
});
