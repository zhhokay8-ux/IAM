/**
 * IAM iframe embed helper.
 * Parent pages MUST pass an explicit targetOrigin. Wildcard "*" is rejected.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.IamEmbed = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  function assertTargetOrigin(targetOrigin) {
    if (!targetOrigin || typeof targetOrigin !== "string" || targetOrigin.trim() === "" || targetOrigin.indexOf("*") >= 0) {
      throw new Error("targetOrigin must be an explicit origin; wildcard is forbidden");
    }
  }

  function postToChild(iframe, message, targetOrigin) {
    assertTargetOrigin(targetOrigin);
    if (!iframe || !iframe.contentWindow) {
      throw new Error("iframe is required");
    }
    iframe.contentWindow.postMessage(message, targetOrigin);
  }

  function acceptParentMessage(event, options) {
    var allowedOrigin = options && options.allowedOrigin;
    var nonce = options && options.nonce;
    var audience = options && options.audience;
    var now = (options && options.now) || Date.now();
    assertTargetOrigin(allowedOrigin);
    if (!event || event.origin !== allowedOrigin) {
      return null;
    }
    var data = event.data || {};
    if (nonce && data.nonce !== nonce) {
      return null;
    }
    if (audience && data.aud !== audience && data.audience !== audience) {
      return null;
    }
    if (data.exp != null && Number(data.exp) * 1000 < now) {
      return null;
    }
    return data;
  }

  return {
    postToChild: postToChild,
    acceptParentMessage: acceptParentMessage
  };
});
