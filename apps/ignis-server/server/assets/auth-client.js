// Sends the tab back to the login page once its session is gone.
//
// A session can expire or be revoked while the app is open. Without this, every request just
// starts failing and the UI looks broken; the server marks those responses with
// X-Ignis-Auth: required, and we turn the first one into a redirect.
// Injected into index.html only when authentication is enabled.
(function () {
  var redirecting = false;

  function toLogin() {
    if (redirecting) {
      return;
    }

    redirecting = true;

    var next = window.location.pathname + window.location.search;
    window.location.replace("/login?next=" + encodeURIComponent(next));
  }

  function isAuthChallenge(status, getHeader) {
    if (status !== 401) {
      return false;
    }

    try {
      return getHeader("X-Ignis-Auth") === "required";
    } catch {
      return false;
    }
  }

  // Read by the Obsidian-side bridge plugin, which puts a sign-out button next to Obsidian's
  // Help action. Its presence is the signal that authentication is on: the server injects this
  // script only then.
  window.__ignisAuth = {
    enabled: true,
    signOut: function () {
      var done = function () {
        redirecting = true;
        window.location.replace("/login");
      };

      // The redirect lands on the login page whether or not the POST got through, so a failed
      // request is not worth blocking on.
      fetch("/logout", {
        method: "POST",
        headers: { Accept: "application/json" },
      }).then(done, done);
    },
  };

  var origFetch = window.fetch;

  if (typeof origFetch === "function") {
    window.fetch = function () {
      return origFetch.apply(this, arguments).then(function (response) {
        if (
          isAuthChallenge(response.status, function (name) {
            return response.headers.get(name);
          })
        ) {
          toLogin();
        }

        return response;
      });
    };
  }

  var origOpen = XMLHttpRequest.prototype.open;

  XMLHttpRequest.prototype.open = function () {
    this.addEventListener("load", function () {
      var xhr = this;

      if (
        isAuthChallenge(xhr.status, function (name) {
          return xhr.getResponseHeader(name);
        })
      ) {
        toLogin();
      }
    });

    return origOpen.apply(this, arguments);
  };
})();
