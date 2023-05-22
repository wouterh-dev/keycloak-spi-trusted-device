<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "title">
    <#elseif section = "header">
        ${msg("trusted-device-header")}
    <#elseif section="form">
      <form id="kc-form-trusted-device" class="${properties.kcFormClass!}"
            action="${url.loginAction}"
            method="post">
        <div class="${properties.kcFormGroupClass!}">
          <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
            <div class="${properties.kcFormOptionsWrapperClass!}">
            </div>
          </div>

          <script>
            function inputName(e) {
              const elem = document.querySelector("#kc-trusted-device-name");
              const result = prompt("${msg("trusted-device-name")}", elem.value);
              if (result === null) {
                e.preventDefault();
                return false;
              }

              elem.value = result;
            }
          </script>

          <input type="hidden" id="kc-trusted-device-name" name="trusted-device-name"
                 value="${trustedDeviceName}"/>

          <div class="${properties.kcFormButtonsClass!}">
              <#if (auth?has_content && auth.showUsername() && !auth.showResetCredentials())>
                <h2 style="margin-top: 0">${msg("trusted-device-header")}</h2>
              </#if>
            <button
                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                name="trusted-device" id="kc-trusted-device-yes"
                type="submit"
                value="yes"
                onclick="inputName(event)">
                ${msg("trusted-device-yes")}
            </button>

            <button
                class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                style="margin-top: 10px"
                name="trusted-device"
                id="kc-trusted-device-no"
                type="submit"
                value="no">
                ${msg("trusted-device-no")}
            </button>

            <div class="${properties.kcInputHelperTextAfterClass!}"
                 id="form-help-text-after-trusted-device"
                 aria-live="polite">
                ${msg("trusted-device-explanation")}
            </div>
          </div>
        </div>
      </form>
    </#if>
</@layout.registrationLayout>
