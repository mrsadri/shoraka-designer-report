/* ---------------------------------------------------------------
   Client-side, two-tier decryption gate.

   Tier 1 — MAIN password: decrypts and shows the ANONYMIZED report
            (names, salaries, companies, phones redacted). Downloads are
            disabled in this state.
   Tier 2 — SECOND password: decrypts the FULL report and the PDFs. Needed
            to turn privacy OFF and to download files.

   The published site is pure ciphertext. Real names/numbers are not even
   present in the main-encrypted payload — only the anonymized text is.
----------------------------------------------------------------*/
(function () {
  "use strict";

  var P = window.PAYLOAD;

  var privacyOn = true; // default ON
  var anonHTML = ""; // tier-1 content (from main password)
  var realHTML = ""; // tier-2 content (from second password)
  var revealKey = null; // AES key from the second password (also decrypts PDFs)

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function deriveKey(password, salt) {
    var base = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: P.iter, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  // blob = iv(12) || ciphertext||tag
  async function decryptBlob(key, blobBytes) {
    var iv = blobBytes.slice(0, 12);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, blobBytes.slice(12));
  }

  var SALT = null; // set on load

  /* ------------------------- toast ------------------------- */
  var toastTimer = null;
  function toast(msg) {
    var t = document.getElementById("pv-toast");
    if (!t) {
      t = document.createElement("div");
      t.id = "pv-toast";
      t.className = "pv-toast";
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      t.classList.remove("show");
    }, 3600);
  }

  /* ------------------------- rendering ------------------------- */
  function render() {
    var report = document.getElementById("report");
    report.innerHTML = privacyOn ? anonHTML : realHTML;
    document.body.classList.toggle("pv-on", privacyOn);
    wireDownloads();
    var sw = document.getElementById("pv-switch");
    if (sw) {
      sw.setAttribute("aria-checked", privacyOn ? "true" : "false");
      sw.classList.toggle("on", privacyOn);
    }
    var st = document.getElementById("pv-state");
    if (st) st.textContent = privacyOn ? "روشن" : "خاموش";
  }

  function wireDownloads() {
    document.querySelectorAll("a.dl[data-enc]").forEach(function (a) {
      a.addEventListener("click", async function (e) {
        e.preventDefault();
        if (privacyOn || !revealKey) {
          toast("برای دانلود، ابتدا حالت حریم خصوصی را با رمز دوم خاموش کنید.");
          return;
        }
        if (a.dataset.busy) return;
        var original = a.innerHTML;
        a.dataset.busy = "1";
        a.style.opacity = "0.6";
        a.innerHTML = '<span class="dl-ic">⏳</span> در حال آماده‌سازی…';
        try {
          var resp = await fetch(a.dataset.enc, { cache: "no-store" });
          if (!resp.ok) throw new Error("fetch " + resp.status);
          var blob = new Uint8Array(await resp.arrayBuffer());
          var plain = await decryptBlob(revealKey, blob);
          var url = URL.createObjectURL(
            new Blob([plain], { type: "application/pdf" })
          );
          var link = document.createElement("a");
          link.href = url;
          link.download = a.dataset.name || "document.pdf";
          document.body.appendChild(link);
          link.click();
          link.remove();
          setTimeout(function () {
            URL.revokeObjectURL(url);
          }, 4000);
        } catch (err) {
          toast("دانلود ناموفق بود. لطفاً دوباره تلاش کنید.");
        } finally {
          a.innerHTML = original;
          a.style.opacity = "";
          delete a.dataset.busy;
        }
      });
    });
  }

  /* ------------------- second-password modal ------------------- */
  // Resolves true if the full tier was unlocked, false if cancelled.
  function askSecondPassword() {
    return new Promise(function (resolve) {
      var back = document.createElement("div");
      back.className = "pv-modal";
      back.innerHTML =
        '<form class="pv-modal-box" autocomplete="off">' +
        '<div class="gate-lock">🔓</div>' +
        '<h2>خاموش‌کردن حریم خصوصی</h2>' +
        '<p class="gate-sub">برای نمایش نام‌ها، مبالغ و نام شرکت‌ها و فعال‌شدن دانلود، رمز دوم را وارد کنید.</p>' +
        '<input type="password" inputmode="text" placeholder="رمز دوم" aria-label="رمز دوم" />' +
        '<button type="submit" class="gate-btn">نمایش کامل</button>' +
        '<button type="button" class="pv-cancel">انصراف</button>' +
        '<p class="gate-error" role="alert" aria-live="assertive"></p>' +
        "</form>";
      document.body.appendChild(back);
      var input = back.querySelector("input");
      var err = back.querySelector(".gate-error");
      var submit = back.querySelector('button[type="submit"]');
      input.focus();

      function close(result) {
        back.remove();
        resolve(result);
      }
      back.querySelector(".pv-cancel").addEventListener("click", function () {
        close(false);
      });
      back.addEventListener("click", function (e) {
        if (e.target === back) close(false);
      });
      back.querySelector("form").addEventListener("submit", async function (e) {
        e.preventDefault();
        err.textContent = "";
        submit.disabled = true;
        var label = submit.textContent;
        submit.textContent = "در حال بررسی…";
        try {
          var key = await deriveKey(input.value, SALT);
          await decryptBlob(key, b64ToBytes(P.rverifier)); // throws if wrong
          var buf = await decryptBlob(key, b64ToBytes(P.full));
          revealKey = key;
          realHTML = new TextDecoder().decode(buf);
          close(true);
        } catch (e2) {
          err.textContent = "رمز دوم نادرست است. دوباره تلاش کنید.";
          input.value = "";
          input.focus();
          submit.disabled = false;
          submit.textContent = label;
        }
      });
    });
  }

  function injectPrivacyControl() {
    if (document.getElementById("privacy-ctl")) return;
    var el = document.createElement("div");
    el.id = "privacy-ctl";
    el.className = "privacy-ctl";
    el.innerHTML =
      '<span class="pv-ic" aria-hidden="true">🕶️</span>' +
      '<span class="pv-label">حریم خصوصی <b id="pv-state">روشن</b></span>' +
      '<button type="button" role="switch" aria-checked="true" id="pv-switch"' +
      ' class="pv-switch on" aria-label="نمایش یا پنهان‌سازی نام‌ها، مبالغ و شرکت‌ها">' +
      '<span class="pv-knob"></span></button>';
    document.body.appendChild(el);
    el.querySelector("#pv-switch").addEventListener("click", async function () {
      if (!privacyOn) {
        // turning ON is free
        privacyOn = true;
        render();
        return;
      }
      // turning OFF requires the second password (once per session)
      if (!revealKey) {
        var ok = await askSecondPassword();
        if (!ok) return; // cancelled / wrong -> stay ON
      }
      privacyOn = false;
      render();
    });
  }

  function reveal(anon) {
    anonHTML = anon;
    document.documentElement.classList.remove("locked");
    var gate = document.getElementById("gate");
    if (gate) gate.remove();
    injectPrivacyControl();
    render(); // privacy ON by default
  }

  /* ----------------------- main gate ----------------------- */
  document.addEventListener("DOMContentLoaded", function () {
    var form = document.getElementById("gate-form");
    var input = document.getElementById("gate-input");
    var error = document.getElementById("gate-error");
    var submit = form ? form.querySelector('button[type="submit"]') : null;

    if (!P || !window.crypto || !crypto.subtle) {
      if (error)
        error.textContent =
          "این مرورگر از رمزگشایی امن پشتیبانی نمی‌کند (به HTTPS و مرورگر به‌روز نیاز است).";
      return;
    }
    SALT = b64ToBytes(P.salt);
    if (input) input.focus();

    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      error.textContent = "";
      submit.disabled = true;
      var oldLabel = submit.textContent;
      submit.textContent = "در حال بررسی…";
      try {
        var key = await deriveKey(input.value, SALT);
        await decryptBlob(key, b64ToBytes(P.verifier)); // throws if wrong
        var buf = await decryptBlob(key, b64ToBytes(P.content));
        reveal(new TextDecoder().decode(buf));
      } catch (err) {
        error.textContent = "رمز نادرست است. دوباره تلاش کنید.";
        input.value = "";
        input.focus();
      } finally {
        submit.disabled = false;
        submit.textContent = oldLabel;
      }
    });
  });
})();
