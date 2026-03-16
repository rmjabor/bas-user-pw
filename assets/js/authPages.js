(function () {
  'use strict';

  const STORAGE_KEYS = {
    RESET_EMAIL: 'basupw_mock_reset_email_v1',
    LOGIN_GUARD: 'basupw_login_guard_v1',
    PENDING_LOGIN_EMAIL: 'basupw_pending_login_email_v1'
  };

  const LOGIN_MAX_ATTEMPTS = 5;
  const LOGIN_LOCK_MINUTES = 15;
  const ASCII_PRINTABLE_NO_CONTROL_REGEX = /^[\x20-\x7E]*$/;
  const MULTIPLE_MIDDLE_SPACES_REGEX = /\S\s{2,}\S/;
  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  function qs(id) {
    return document.getElementById(id);
  }

  function getSupabaseClient() {
    return window.basupwSupabase || window.supabaseClient || null;
  }

  function getBootstrapModal(element) {
    if (!element || !window.bootstrap || !window.bootstrap.Modal) return null;
    return window.bootstrap.Modal.getOrCreateInstance(element);
  }

  function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
  }

  function looksLikeEmail(email) {
    return EMAIL_REGEX.test(String(email || '').trim());
  }

  function stripNonPrintableAscii(value) {
    return Array.from(String(value || '')).filter(char => {
      const code = char.charCodeAt(0);
      return code >= 32 && code <= 126;
    }).join('');
  }

  function getTrimmedPassword(password) {
    return String(password || '').replace(/^\s+|\s+$/g, '');
  }

  function getPasswordLengthForPolicy(password) {
    return getTrimmedPassword(password).length;
  }

  function isAsciiPrintablePassword(password) {
    return ASCII_PRINTABLE_NO_CONTROL_REGEX.test(String(password || ''));
  }

  function loadLoginGuard() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.LOGIN_GUARD);
      const parsed = raw ? JSON.parse(raw) : null;
      return {
        count: parsed?.count || 0,
        lockUntil: parsed?.lockUntil || 0
      };
    } catch {
      return { count: 0, lockUntil: 0 };
    }
  }

  function saveLoginGuard(data) {
    localStorage.setItem(STORAGE_KEYS.LOGIN_GUARD, JSON.stringify(data));
  }

  function clearLoginGuard() {
    localStorage.removeItem(STORAGE_KEYS.LOGIN_GUARD);
  }

  function getRemainingLockMinutes(lockUntil) {
    return Math.max(1, Math.ceil((lockUntil - Date.now()) / 60000));
  }

  function setButtonEnabledState(button, enabled) {
    if (!button) return;
    button.disabled = !enabled;
    button.style.opacity = enabled ? '1' : '0.55';
    button.style.cursor = enabled ? 'pointer' : 'not-allowed';
  }

  function setButtonText(button, text) {
    if (button) button.textContent = text;
  }

  function togglePasswordVisibility(input, icon) {
    if (!input || !icon) return;
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    icon.classList.toggle('ion-eye', !reveal);
    icon.classList.toggle('ion-eye-disabled', reveal);
  }

  function sanitizePasswordInput(input) {
    if (!input) return;
    const sanitized = stripNonPrintableAscii(input.value);
    if (input.value !== sanitized) input.value = sanitized;
  }

  function getBaseRedirectUrl() {
    const path = window.location.pathname;
    const lastSlash = path.lastIndexOf('/');
    const directory = lastSlash >= 0 ? path.slice(0, lastSlash + 1) : '/';
    return `${window.location.origin}${directory}`;
  }

  function buildPageUrl(page) {
    return `${getBaseRedirectUrl()}${page}`;
  }

  function getFriendlyAuthErrorMessage(error, fallback) {
    const message = String(error?.message || '').toLowerCase();

    if (message.includes('invalid login credentials')) {
      return 'Não foi possível realizar o login. Verifique o e-mail e a senha.';
    }

    if (message.includes('email not confirmed')) {
      return 'Seu e-mail ainda não foi confirmado.';
    }

    return fallback || 'Não foi possível concluir a operação.';
  }

  async function initCadastroPage() {
    const supabase = getSupabaseClient();

    const emailInput = qs('inputEmailCadastro');
    const firstNameInput = qs('inputNomeCadastro');
    const lastNameInput = qs('inputSobrenomeCadastro');
    const passwordInput = qs('inputSenhaCadastro');
    const submitButton = qs('btnCadastrar');

    if (!emailInput || !passwordInput || !submitButton) return;

    const { data } = await supabase.auth.getSession();
    if (data?.session) {
      window.location.href = 'home.html';
      return;
    }

    submitButton.addEventListener('click', async () => {

      const { error } = await supabase.auth.signUp({
        email: emailInput.value.trim(),
        password: getTrimmedPassword(passwordInput.value),
        options: {
          emailRedirectTo: buildPageUrl('entrar.html'),
          data: {
            first_name: firstNameInput.value.trim(),
            last_name: lastNameInput.value.trim()
          }
        }
      });

      if (error) {
        alert(getFriendlyAuthErrorMessage(error));
        return;
      }

      sessionStorage.setItem(STORAGE_KEYS.PENDING_LOGIN_EMAIL, emailInput.value.trim());
      alert('Cadastro realizado. Verifique seu e-mail para confirmar.');
      window.location.href = 'entrar.html';

    });
  }

  async function initEntrarPage() {
    const supabase = getSupabaseClient();

    const emailInput = qs('inputEmailEntrar');
    const passwordInput = qs('inputSenhaEntrar');
    const submitButton = qs('btnEntrar');

    if (!emailInput || !passwordInput || !submitButton) return;

    const { data } = await supabase.auth.getSession();
    if (data?.session) {
      window.location.href = 'home.html';
      return;
    }

    submitButton.addEventListener('click', async () => {

      const guard = loadLoginGuard();

      if (guard.lockUntil > Date.now()) {
        alert(`Tente novamente em ${getRemainingLockMinutes(guard.lockUntil)} minutos.`);
        return;
      }

      const { error } = await supabase.auth.signInWithPassword({
        email: emailInput.value.trim(),
        password: getTrimmedPassword(passwordInput.value)
      });

      if (error) {

        const next = guard.count + 1;

        if (next >= LOGIN_MAX_ATTEMPTS) {
          const lockUntil = Date.now() + LOGIN_LOCK_MINUTES * 60000;
          saveLoginGuard({ count: next, lockUntil });
          alert(`Excesso de tentativas. Tente novamente em ${LOGIN_LOCK_MINUTES} minutos.`);
        } else {
          saveLoginGuard({ count: next, lockUntil: 0 });
          alert(getFriendlyAuthErrorMessage(error));
        }

        return;
      }

      clearLoginGuard();
      window.location.href = 'home.html';

    });
  }

  async function initHomePage() {
    const supabase = getSupabaseClient();
    const btnLogout = qs('btnLogoutHome');

    if (!btnLogout) return;

    btnLogout.addEventListener('click', async () => {

      try {

        console.log('[BAS_UPW] Logout iniciado');

        setButtonEnabledState(btnLogout, false);
        setButtonText(btnLogout, 'Saindo...');

        await supabase.auth.signOut();

        console.log('[BAS_UPW] Logout realizado');

        window.location.href = 'entrar.html';

      } catch (error) {

        console.error('[BAS_UPW] Erro no logout:', error);

        setButtonEnabledState(btnLogout, true);
        setButtonText(btnLogout, 'Logout');

      }

    });
  }

  function initSharedUiBehaviors() {

    const modalRedef = qs('mdlRedefSenha');
    const inputEmailRedef = qs('inputEmailLinkRedef');

    if (modalRedef && inputEmailRedef) {

      modalRedef.addEventListener('hidden.bs.modal', () => {
        inputEmailRedef.value = '';
      });

    }

  }

  document.addEventListener('DOMContentLoaded', async () => {

    initSharedUiBehaviors();

    await initCadastroPage();
    await initEntrarPage();
    await initHomePage();

  });

})();