define(['baseView', 'loading', 'globalize', 'emby-input', 'emby-button', 'emby-checkbox', 'emby-scroller'], function (BaseView, loading, globalize) {
    'use strict';

    var pluginId = 'ad89f430-b0d0-4e9a-996d-c088f6961158';

    function showUrls(page, baseUrl) {
        var base = (baseUrl || '').replace(/[\/]+$/, '');
        page.querySelector('#redirectUri').textContent = base + '/sso/callback';
        page.querySelector('#startUrl').textContent = base + '/sso/start';
        page.querySelector('#pinUrl').textContent = base + '/sso/pin';
    }

    // Admin-only endpoints on this plugin's own service. Fails quietly: the
    // server id and the buy link are conveniences, and losing them must not
    // stop the rest of the page working.
    function showActivation(page) {
        ApiClient.getJSON(ApiClient.getUrl('Sso/Activation')).then(function (info) {
            page.querySelector('#serverId').textContent = info.ServerId || '';

            var buyLink = page.querySelector('#buyLink');
            buyLink.href = info.BuyUrl || '#';
            buyLink.style.display = info.BuyUrl ? '' : 'none';
        }, function () {
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
            url: ApiClient.getUrl('Sso/Activate'),
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
        page.querySelector('#enableButtonInjection').checked = config.EnableButtonInjection === true;
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
            config.EnableButtonInjection = form.querySelector('#enableButtonInjection').checked;
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
