define(['baseView', 'loading', 'globalize', 'emby-input', 'emby-button', 'emby-checkbox', 'emby-scroller'], function (BaseView, loading, globalize) {
    'use strict';

    var pluginId = 'ad89f430-b0d0-4e9a-996d-c088f6961158';

    function showUrls(page, baseUrl) {
        var base = (baseUrl || '').replace(/[\/]+$/, '');
        page.querySelector('#redirectUri').textContent = base + '/emby/Sso/Callback';
        page.querySelector('#startUrl').textContent = base + '/emby/Sso/Start';
    }

    function loadPage(page, config) {
        page.querySelector('#issuerUrl').value = config.IssuerUrl || '';
        page.querySelector('#clientId').value = config.ClientId || '';
        page.querySelector('#clientSecret').value = config.ClientSecret || '';
        page.querySelector('#scopes').value = config.Scopes || 'openid profile email';
        page.querySelector('#embyPublicBaseUrl').value = config.EmbyPublicBaseUrl || '';
        page.querySelector('#usernameClaim').value = config.UsernameClaim || 'preferred_username';
        page.querySelector('#enableDirectGrant').checked = config.EnableDirectGrant === true;
        page.querySelector('#enableButtonInjection').checked = config.EnableButtonInjection === true;
        page.querySelector('#allowInsecureHttp').checked = config.AllowInsecureHttp === true;
        page.querySelector('#allowPrivateNetworkProvider').checked = config.AllowPrivateNetworkProvider === true;
        page.querySelector('#requiredGroup').value = config.RequiredGroup || '';
        page.querySelector('#groupsClaim').value = config.GroupsClaim || 'groups';
        page.querySelector('#templateUserName').value = config.TemplateUserName || '';
        page.querySelector('#enableAutoCreate').checked = config.EnableAutoCreate === true;
        showUrls(page, config.EmbyPublicBaseUrl);

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
            config.EnableButtonInjection = form.querySelector('#enableButtonInjection').checked;
            config.AllowInsecureHttp = form.querySelector('#allowInsecureHttp').checked;
            config.AllowPrivateNetworkProvider = form.querySelector('#allowPrivateNetworkProvider').checked;
            config.RequiredGroup = form.querySelector('#requiredGroup').value.trim();
            config.GroupsClaim = form.querySelector('#groupsClaim').value.trim();
            config.TemplateUserName = form.querySelector('#templateUserName').value.trim();
            config.EnableAutoCreate = form.querySelector('#enableAutoCreate').checked;

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
